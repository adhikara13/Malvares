import argparse
import os

def xor_decrypt(data, key=0x5E):
    return bytes([b ^ key for b in data])

def read_and_decrypt(filepath):
    if not os.path.exists(filepath):
        print(f"[-] ERROR: File not found -> {filepath}")
        return

    try:
        with open(filepath, "rb") as f:
            encrypted_data = f.read()
        decrypted_data = xor_decrypt(encrypted_data)

        print(f"\n[+] Decrypted Poolrat Configuration from: {filepath}")
        print("-" * 60)
        print(decrypted_data.decode(errors='ignore'))
        print("-" * 60)

    except Exception as e:
        print(f"[-] ERROR: Cannot read {filepath}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Decrypt POOLRAT config file using XOR key 0x5E.")
    parser.add_argument("--file", type=str, help="Specify a POOLRAT config file. Defaults to /etc/apdl.cf.")
    args = parser.parse_args()

    filepath = args.file if args.file else "/etc/apdl.cf"
    read_and_decrypt(filepath)

if __name__ == "__main__":
    main()
