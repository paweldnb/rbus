def extract_unique_registers(input_file: str, output_file: str):
    registers = set()

    with open(input_file, 'r') as f:
        for line in f:
            parts = line.strip().split("||")
            if len(parts) >= 3:
                register_hex = parts[1].strip()
                if register_hex:  # unikaj pustych
                    registers.add(register_hex.lower())

    with open(output_file, 'w') as f:
        for reg in sorted(registers):
            f.write(reg + '\n')

    print(f"Found {len(registers)} unique register.")
    print(f"Seve to: {output_file}")

if __name__ == "__main__":
    extract_unique_registers(
        input_file="decoded-sniffed-hex-special3.log",
        output_file="unique-registers3.log"
    )
