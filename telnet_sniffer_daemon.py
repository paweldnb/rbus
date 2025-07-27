import re
import threading
import telnetlib
import time
import os
import sys
import atexit
from signal import signal, SIGTERM
from collections import defaultdict

# ===== PATHS =====
BASE = "/shared/downloads/pawel/dedietrich/"
SNIFF_FILE = BASE + "sniffed-hex.log"
DECODED_FILE = BASE + "decoded-sniffed-hex.log"
UNMATCHED_FILE = BASE + "decoded-sniffed-hex-unmatched.log"
SPECIAL_FILE = BASE + "decoded-sniffed-hex-special.log"
GROUPED_FILE = BASE + "grouped-registers.log"
UNIQUE_REG_FILE = BASE + "unique-registers.log"
PID_FILE = "/tmp/dd_telnet_pipeline.pid"

# ===== CONFIG =====
HOST = "192.168.1.115"
PORT = 23
LOOP_DELAY = 5  # seconds

# ===== SNIFFER – RAW BYTE LOGGER =====
def log_telnet_hex():
    try:
        tn = telnetlib.Telnet(HOST, PORT, timeout=10)
        with open(SNIFF_FILE, "ab") as f:
            while True:
                data = tn.read_very_eager()
                if data:
                    f.write(data)  # <-- key change: writing raw bytes
                    f.flush()
                time.sleep(0.2)
    except Exception as e:
        with open("/tmp/dd_sniffer_error.log", "a") as f:
            f.write(str(e) + "\n")

# ===== BINARY LOG READER =====
def read_hex_file(filepath: str) -> bytes:
    with open(filepath, 'r') as f:
        hex_string = f.read()

    # Remove all non-hex characters
    hex_string = re.sub(r'[^0-9a-fA-F]', '', hex_string)

    # Ensure even number of characters
    if len(hex_string) % 2 != 0:
        hex_string = hex_string[:-1]

    return bytes.fromhex(hex_string)

# ===== CONVERT BYTES TO PRINTABLE ASCII =====
def bytes_to_printable_ascii(b: bytes) -> str:
    return ''.join([chr(x) if 32 <= x < 127 else '.' for x in b])

# ===== FRAME PARSING + TAIL BUFFERING =====
def parse_frames(data: bytes):
    index = 0
    matched, unmatched, special = [], [], []
    msg_num, unmatched_num, special_num = 1, 1, 1

    while index < len(data) - 1:
        if data[index:index+2] == b'\x01\x00':
            if index + 8 > len(data): break
            payload_len = data[index+4]
            frame_len = 8 + payload_len
            if index + frame_len > len(data): break

            frame = data[index:index+frame_len]
            header = frame[0:2].hex()
            req_reply = frame[2:3].hex()
            flags = frame[3:4].hex()
            payload_len_hex = frame[4:5].hex()
            unknown = frame[5:8]
            unknown_hex = unknown.hex()
            payload = frame[8:]
            payload_hex = payload.hex()
            payload_ascii = bytes_to_printable_ascii(payload)
            u16 = str(int.from_bytes(payload[-2:], 'little')) if len(payload) >= 2 else "--"

            matched.append(f"[{msg_num}] {header}|{req_reply}|{flags}|{unknown_hex}|{payload_hex}|{payload_ascii}||{u16}")

            if unknown.startswith(b'\xf3') or unknown.startswith(b'\xfa'):
                reg = payload[:3].hex() if len(payload) >= 3 else payload.hex()
                rest = payload[3:].hex() if len(payload) > 3 else ''
                ascii_full = bytes_to_printable_ascii(payload)
                if len(payload) >= 4:
                    u1 = int.from_bytes(payload[-4:-2], 'little')
                    u2 = int.from_bytes(payload[-2:], 'little')
                    uval = f"{u1},{u2}"
                else:
                    uval = "--,--"
                special.append(f"[{special_num}] {header}|{req_reply}|{flags}|{unknown_hex}||{reg}|{rest}||{ascii_full}||{uval}")
                special_num += 1

            index += frame_len
            msg_num += 1
        else:
            start = index
            while index < len(data) - 1 and data[index:index+2] != b'\x01\x00':
                index += 1
            unmatched_chunk = data[start:index]
            if unmatched_chunk:
                unmatched.append(f"[{unmatched_num}] {unmatched_chunk.hex()}")
                unmatched_num += 1

    tail = data[index:]  # incomplete frame
    return matched, unmatched, special, tail

# ===== WRITE TO FILE =====
def write_output(filepath: str, lines: list[str]):
    with open(filepath, 'w') as f:
        for line in lines:
            f.write(line + '\n')

# ===== GROUP BY REGISTER ID =====
def group_registers(input_file: str, output_file: str):
    groups = defaultdict(list)
    with open(input_file, 'r') as f:
        for line in f:
            parts = line.strip().split("||")
            if len(parts) >= 3:
                reg = parts[1].strip().lower()
                groups[reg].append(line.strip())
    with open(output_file, 'w') as f:
        for reg, lines in sorted(groups.items()):
            f.write(f"=== register: {reg} ===\n")
            for l in lines:
                f.write(l + '\n')
            f.write("\n")

# ===== EXTRACT UNIQUE REGISTERS =====
def extract_unique_registers(input_file: str, output_file: str):
    regs = set()
    with open(input_file, 'r') as f:
        for line in f:
            parts = line.strip().split("||")
            if len(parts) >= 3:
                reg = parts[1].strip().lower()
                if reg:
                    regs.add(reg)
    with open(output_file, 'w') as f:
        for r in sorted(regs):
            f.write(r + '\n')

# ===== MAIN PIPELINE =====
def run_pipeline():
    prev_tail = b""
    log_pid = os.fork()

    if log_pid == 0:
        # Sniffer – subprocess
        log_telnet_hex()
        sys.exit(0)

    while True:
        try:
            raw = read_hex_file(SNIFF_FILE)
            data = prev_tail + raw
            matched, unmatched, special, tail = parse_frames(data)
            prev_tail = tail

            write_output(DECODED_FILE, matched)
            write_output(UNMATCHED_FILE, unmatched)
            write_output(SPECIAL_FILE, special)
            group_registers(SPECIAL_FILE, GROUPED_FILE)
            extract_unique_registers(SPECIAL_FILE, UNIQUE_REG_FILE)
        except Exception as e:
            with open("/tmp/dd_pipeline_error.log", "a") as f:
                f.write(str(e) + '\n')
        time.sleep(LOOP_DELAY)

# ===== DAEMON HANDLER =====
def daemonize():
    if os.path.exists(PID_FILE):
        print("Daemon is already running.")
        sys.exit(1)

    pid = os.fork()
    if pid > 0: sys.exit(0)
    os.setsid()
    pid = os.fork()
    if pid > 0: sys.exit(0)

    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))
    atexit.register(lambda: os.remove(PID_FILE))
    signal(SIGTERM, lambda *_: sys.exit(0))

    run_pipeline()

# ===== ENTRY POINT =====
if __name__ == "__main__":
    threading.Thread(target=log_telnet_hex, daemon=True).start()
    run_pipeline()
