import telnetlib
import re
from datetime import datetime
import time
import os

# ===== KONFIGURACJA =====
HOST = "x.x.x.x"
PORT = 23
BASE = "/shared/downloads/xxxxx/dedietrich/"

LOG_FILE_ALL = os.path.join(BASE, "decoded-sniffed-hex.log")
GROUP_PREFIX = os.path.join(BASE, "decoded-group-")



def sanitize_hex_string(hex_str: str) -> str:
    return re.sub(r'[^0-9a-fA-F]', '', hex_str)

def bytes_from_hexstream(s: str) -> bytes:
    clean = sanitize_hex_string(s)
    if len(clean) % 2 != 0:
        clean = clean[:-1]
    return bytes.fromhex(clean)

def bytes_to_printable_ascii(b: bytes) -> str:
    return ''.join(chr(x) if 32 <= x < 127 else '.' for x in b)

def log_to_file(filepath: str, line: str):
    with open(filepath, 'a') as f:
        f.write(line + '\n')


def parse_frames(data: bytes):
    index = 0
    matched = []

    while index < len(data) - 1:
        ts = datetime.now().isoformat(timespec='milliseconds')

        if data[index:index+2] == b'\x01\x00':
            if index + 8 > len(data):
                break

            payload_len = data[index + 4]
            frame_len = 8 + payload_len
            if index + frame_len > len(data):
                break

            frame = data[index:index + frame_len]
            header = frame[0:2].hex()
            req_reply = frame[2:3].hex()
            flags = frame[3:4].hex()
            payload_len_hex = frame[4:5].hex()
            unknown = frame[5:8]
            unknown_hex = unknown.hex()
            payload = frame[8:]
            payload_hex = payload.hex()
            payload_ascii = bytes_to_printable_ascii(payload[3:]) if len(payload) > 3 else ""

            value = "--"
            if len(payload) >= 2:
                raw = int.from_bytes(payload[-2:], byteorder='little')
                value = f"{raw / 1000:.3f}".replace('.', ',')

            line = f"{ts} {header}|{req_reply}|{flags}|{payload_len_hex}|{unknown_hex}|{payload_hex}[payload->]{payload_ascii}||{value}"
            matched.append(line)

            # zapis do grupy
            if len(payload) >= 3:
                payload_key = payload[0:3].hex()
                group_file = os.path.join(BASE, f"decoded-group-{payload_key}.log")
            else:
                group_file = os.path.join(BASE, "decoded-group-invalid.log")

            log_to_file(group_file, line)

            index += frame_len
        else:
            index += 1

    tail = data[index:]
    return matched, tail

def main():
    print(f"Connecting to {HOST}:{PORT}...")
    tn = telnetlib.Telnet(HOST, PORT, timeout=10)
    print("Connected.")

    buffer = ""
    tail = b""

    try:
        while True:
            raw = tn.read_very_eager().decode(errors='ignore')
            if raw:
                buffer += raw
                bytes_in = tail + bytes_from_hexstream(buffer)
                matched, tail = parse_frames(bytes_in)

                for line in matched:
                    log_to_file(LOG_FILE_ALL, line)

                buffer = ""
            time.sleep(0.1)

    except KeyboardInterrupt:
        print("\n[EXIT] Program przerwany przez użytkownika.")
    except Exception as e:
        print("ERROR:", e)

if __name__ == "__main__":
    main()
