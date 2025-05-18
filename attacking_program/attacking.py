#!/usr/bin/env python3

import socket
import struct
import argparse
import sys
import getpass

def recvall(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=5555)
    args = parser.parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((args.host, args.port))
    s.listen(1)
    print(f"[*] Listening on {args.host}:{args.port}")

    while True:
        conn, addr = s.accept()
        print(f"[+] Connection from {addr}")

        while True:
            password = getpass.getpass("Password: ")
            payload = password.encode()
            conn.send(struct.pack("!I", len(payload)) + payload)

            conn.settimeout(1.0)
            try:
                peek = conn.recv(1)
                if not peek:
                    print("Wrong password, try again.")
                    conn.close()
                    break
                else:
                    leftover = peek
                    conn.settimeout(None)
                    print("[+] Authenticated, entering shell.")
                    goto_shell = True
                    break
            except socket.timeout:
                conn.settimeout(None)
                print("[+] Authenticated, entering shell.")
                leftover = b''
                goto_shell = True
                break

        if not 'goto_shell' in locals() or not goto_shell:
            continue

        try:
            while True:
                cmd = input("shell> ")
                if not cmd:
                    continue
                data = cmd.encode()
                conn.send(struct.pack('!I', len(data)) + data)

                raw = recvall(conn, 4)
                if not raw:
                    print("[-] Disconnected.")
                    break
                out_len = struct.unpack('!I', raw)[0]

                resp = recvall(conn, out_len)
                if resp is None:
                    print("[-] Disconnected.")
                    break

                sys.stdout.write(resp.decode())
        except KeyboardInterrupt:
            print("\n[!] Exit.")
        finally:
            conn.close()
        break

    s.close()

if __name__ == '__main__':
    main()
