import socket
import struct
import os
import sys

HOST = "192.168.120.1"
PORT = 69
ROOT = os.path.dirname(os.path.abspath(__file__))

OPCODE_RRQ = 1
OPCODE_WRQ = 2
OPCODE_DATA = 3
OPCODE_ACK = 4
OPCODE_ERROR = 5

def handle_wrq(filename, addr):
    print(f"[WRQ] {addr} -> {filename}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, 0))
    sock.settimeout(10)
    # send ACK 0
    sock.sendto(struct.pack("!HH", OPCODE_ACK, 0), addr)
    filepath = os.path.join(ROOT, os.path.basename(filename))
    data = b""
    block = 1
    with open(filepath, "wb") as f:
        while True:
            try:
                pkt, raddr = sock.recvfrom(516)
            except socket.timeout:
                print("Timeout waiting for data")
                break
            opcode = struct.unpack("!H", pkt[:2])[0]
            if opcode == OPCODE_DATA:
                blk_num = struct.unpack("!H", pkt[2:4])[0]
                payload = pkt[4:]
                f.write(payload)
                sock.sendto(struct.pack("!HH", OPCODE_ACK, blk_num), raddr)
                if len(payload) < 512:
                    print(f"[WRQ] done, saved to {filepath}, size={f.tell()}")
                    break
    sock.close()

def handle_rrq(filename, addr):
    print(f"[RRQ] {addr} -> {filename}")
    filepath = os.path.join(ROOT, os.path.basename(filename))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, 0))
    sock.settimeout(10)
    if not os.path.exists(filepath):
        sock.sendto(struct.pack("!HH", OPCODE_ERROR, 1) + b"File not found\x00", addr)
        sock.close()
        return
    with open(filepath, "rb") as f:
        block = 1
        while True:
            chunk = f.read(512)
            sock.sendto(struct.pack("!HH", OPCODE_DATA, block) + chunk, addr)
            try:
                pkt, raddr = sock.recvfrom(516)
            except socket.timeout:
                print("Timeout waiting for ACK")
                break
            opcode, ackblk = struct.unpack("!HH", pkt[:4])
            if opcode == OPCODE_ACK and ackblk == block:
                if len(chunk) < 512:
                    print(f"[RRQ] done sending {filepath}")
                    break
                block += 1
    sock.close()

def main():
    print(f"TFTP server listening on {HOST}:{PORT}, root={ROOT}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
    while True:
        pkt, addr = sock.recvfrom(516)
        opcode = struct.unpack("!H", pkt[:2])[0]
        parts = pkt[2:].split(b"\x00")
        filename = parts[0].decode()
        mode = parts[1].decode() if len(parts) > 1 else "octet"
        if opcode == OPCODE_WRQ:
            handle_wrq(filename, addr)
        elif opcode == OPCODE_RRQ:
            handle_rrq(filename, addr)

if __name__ == "__main__":
    main()
