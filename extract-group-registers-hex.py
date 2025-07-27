from collections import defaultdict

def group_registers_single_file(input_file: str, output_file: str):
    groups = defaultdict(list)

    with open(input_file, 'r') as f:
        for line in f:
            parts = line.strip().split("||")
            if len(parts) >= 3:
                register = parts[1].strip().lower()
                groups[register].append(line.strip())

    with open(output_file, 'w') as f:
        for register, lines in sorted(groups.items()):
            f.write(f"=== register: {register} ===\n")
            for line in lines:
                f.write(line + '\n')
            f.write("\n")

    print(f"📄 Saved grouped matched frames: {output_file}")
    print(f"🔢 Count unique registers : {len(groups)}")

if __name__ == "__main__":
    input_path = "decoded-sniffed-hex-special3.log"
    output_path = "grouped-registers3.log"

    group_registers_single_file(input_path, output_path)
