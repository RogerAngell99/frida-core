from pathlib import Path
import random
import string
import sys

import lief


def random_token(alphabet: str, length: int) -> str:
    return "".join(random.choice(alphabet) for _ in range(length))


def replace_fixed(data: bytes, needle: bytes, replacement: bytes) -> bytes:
    if len(needle) != len(replacement):
        raise ValueError("replacement must preserve length")
    return data.replace(needle, replacement)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: anti-anti-frida.py <binary>", file=sys.stderr)
        return 1

    input_file = Path(argv[1])
    print(f"[*] Patch frida-agent: {input_file}")

    binary = lief.parse(str(input_file))
    if binary is None:
        print("[!] Unable to parse binary with LIEF", file=sys.stderr)
        return 1

    symbol_token = random_token(string.ascii_uppercase[:15], 5)
    print(f"[*] Patch `frida` symbol token to `{symbol_token}`")

    for symbol in binary.symbols:
        if symbol.name == "frida_agent_main":
            symbol.name = "main"
        elif "frida" in symbol.name:
            symbol.name = symbol.name.replace("frida", symbol_token)
        elif "FRIDA" in symbol.name:
            symbol.name = symbol.name.replace("FRIDA", symbol_token)

    binary.write(str(input_file))

    data = input_file.read_bytes()

    thread_token = random_token(string.ascii_lowercase[:14], len("gum-js-loop"))
    print(f"[*] Patch `gum-js-loop` to `{thread_token}`")
    data = replace_fixed(data, b"gum-js-loop", thread_token.encode())

    gmain_token = random_token(string.ascii_lowercase[:14], len("gmain"))
    print(f"[*] Patch `gmain` to `{gmain_token}`")
    data = replace_fixed(data, b"gmain", gmain_token.encode())

    input_file.write_bytes(data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
