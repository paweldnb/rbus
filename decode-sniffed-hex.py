import re

def read_hex_file(filepath: str) -> bytes:
    with open(filepath, 'r') as f:
        hex_string = f.read()

    # Usuwamy znaki niebędące hexem
    hex_string = re.sub(r'[^0-9a-fA-F]', '', hex_string)

    # Zapewniamy parzystą liczbę znaków
    if len(hex_string) % 2 != 0:
        hex_string = hex_string[:-1]

    return bytes.fromhex(hex_string)

def bytes_to_printable_ascii(b: bytes) -> str:
    return ''.join([chr(x) if 32 <= x < 127 else '.' for x in b])

def parse_frames(data: bytes) -> tuple[list[str], list[str], list[str]]:
    index = 0
    matched_lines = []
    unmatched_chunks = []
    special_lines = []
    message_num = 1
    unmatched_num = 1
    special_num = 1

    while index < len(data) - 1:
        if data[index:index+2] == b'\x01\x00':
            if index + 8 > len(data):
                matched_lines.append(f"[{message_num}] ERROR: Incomplete frame at end of data.")
                break

            payload_len = data[index+4]
            frame_len = 8 + payload_len

            if index + frame_len > len(data):
                matched_lines.append(f"[{message_num}] ERROR: Incomplete payload at position {index}")
                break

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

            # Dekodowanie ostatnich 2 bajtów jako uint16
            if len(payload) >= 2:
                payload_u16 = int.from_bytes(payload[-2:], byteorder='little')
                u16_str = str(payload_u16)
            else:
                u16_str = "--"

            # Główna ramka: zapis do decoded-sniffed-hex2.log
            output_line = (
                f"[{message_num}] {header}|{req_reply}|{flags}|{payload_len_hex}|"
                f"{unknown_hex}|{payload_hex}|{payload_ascii}||{u16_str}"
            )
            matched_lines.append(output_line)

            # Ramki specjalne
            if unknown.startswith(b'\xf3') or unknown.startswith(b'\xfa'):
                register = payload[:3] if len(payload) >= 3 else payload
                payload_rest = payload[3:] if len(payload) > 3 else b''

                register_hex = register.hex()
                payload_rest_hex = payload_rest.hex()
                payload_ascii_full = bytes_to_printable_ascii(payload)

                if len(payload) >= 4:
                    u16_1 = int.from_bytes(payload[-4:-2], byteorder='little')
                    u16_2 = int.from_bytes(payload[-2:], byteorder='little')
                    u16_part = f"{u16_1},{u16_2}"
                else:
                    u16_part = "--,--"

                special_line = (
                    f"[{special_num}] {header}|{req_reply}|{flags}|{payload_len_hex}|{unknown_hex}||"
                    f"{register_hex}|{payload_rest_hex}||{payload_ascii_full}||{u16_part}"
                )
                special_lines.append(special_line)
                special_num += 1

            index += frame_len
            message_num += 1
        else:
            unmatched_start = index
            while index < len(data) - 1 and data[index:index+2] != b'\x01\x00':
                index += 1
            unmatched_chunk = data[unmatched_start:index]
            if unmatched_chunk:
                line = f"[{unmatched_num}] {unmatched_chunk.hex()}"
                unmatched_chunks.append(line)
                unmatched_num += 1

    return matched_lines, unmatched_chunks, special_lines

def write_output(filepath: str, lines: list[str]):
    with open(filepath, 'w') as f:
        for line in lines:
            f.write(line + '\n')

if __name__ == "__main__":
    input_path = "sniffed-hex3.log"
    output_matched = "decoded-sniffed-hex3.log"
    output_unmatched = "decoded-sniffed-hex-unmatched3.log"
    output_special = "decoded-sniffed-hex-special3.log"

    data = read_hex_file(input_path)
    matched, unmatched, special = parse_frames(data)

    write_output(output_matched, matched)
    write_output(output_unmatched, unmatched)
    write_output(output_special, special)

    print(f"✅ Saved {len(matched)} matched frames: {output_matched}")
    print(f"⚠️  Saved {len(unmatched)} unmatched frames: {output_unmatched}")
    print(f"⭐ Saved {len(special)} matched special frames req/ans: {output_special}")
    print("\nFormat (hex2): [n] header|req/reply|flags|payload_len|unknown|payload_hex|payload_ascii||uint16")
    print("Format (special2): [n] header|req/reply|flags|payload_len|unknown||register|payload_rest||payload_ascii||uint16_1,uint16_2")

