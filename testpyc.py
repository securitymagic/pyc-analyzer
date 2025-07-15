import sys
import base64
import re
import marshal
import dis
from types import CodeType
import struct

PYTHON_MAGIC_SIZE = 16  # 4 (magic) + 4 (bitfield) + 8 (timestamp/hash)

COMMON_CIPHER_HINTS = ["AES", "RC4", "ROT", "DES", "BLOWFISH", "CHACHA", "CHACHA20"]

def is_base64_string(s):
    try:
        return base64.b64encode(base64.b64decode(s)) == s.encode()
    except Exception:
        return False

def is_hex_string(s):
    return re.fullmatch(r'[0-9a-fA-F]+', s) and len(s) % 2 == 0

def is_suspicious_bytes(blob, min_length=64):
    if not isinstance(blob, (bytes, bytearray)):
        return False
    if len(blob) < min_length:
        return False
    return True
KNOWN_MAGIC_HEADERS = {
    b'\xfd7zXZ': 'xz compressed',
    b'PK\x03\x04': 'zip archive',
    b"\x1f\x8b": "GZIP compressed data",
    b'\x78\x9c': 'zlib',
    b'\x42\x5a\x68': 'bzip2',
    b"MZ": "Windows PE file",
    b'\x7fELF': 'ELF executable',
}

def detect_magic_type(blob):
    for magic, label in KNOWN_MAGIC_HEADERS.items():
        if blob.startswith(magic):
            return label
    return 'unknown binary blob'


def detect_python_version(pyc_path):
    with open(pyc_path, "rb") as f:
        magic = f.read(4)
        version = struct.unpack("<H", magic[:2])[0]
        return version

def find_cipher_mentions(code_obj, path=""):
    hits = []
    for const in code_obj.co_consts:
        if isinstance(const, str):
            for cipher in COMMON_CIPHER_HINTS:
                if cipher.lower() in const.lower():
                    hits.append((path or "<module>", f"Heuristic: Found '{cipher}' in string — may indicate {cipher} encryption"))
        elif isinstance(const, CodeType):
            sub_path = f"{path}->{const.co_name}" if path else const.co_name
            hits.extend(find_cipher_mentions(const, sub_path))
    return hits

def find_decode_pipeline(code_obj):
    pipeline = []
    xor_funcs = {}
    exec_triggered = False
    const_assignments = {}
    pending_calls = []

    try:
        instructions = list(dis.get_instructions(code_obj))
    except Exception as e:
        print(f"[!] Skipping decode pipeline disassembly: {e}")
        return pipeline

    for i, instr in enumerate(instructions):
        if instr.opname == "LOAD_CONST" and isinstance(instr.argval, CodeType):
            nested_code = instr.argval
            try:
                nested_instrs = list(dis.get_instructions(nested_code))
                if any(i.opname == "BINARY_XOR" for i in nested_instrs):
                    xor_funcs[instr.offset] = nested_code
                    pipeline.append("XOR function detected (lambda or function)")
            except Exception as e:
                print(f"[!] Skipping nested XOR check in pipeline: {e}")

        elif instr.opname == "STORE_NAME":
            if i > 0 and instructions[i-1].opname == "LOAD_CONST":
                const_assignments[instr.argval] = instructions[i-1].argval

        elif instr.opname == "LOAD_NAME":
            pending_calls.append(instr.argval)

        elif instr.opname == "CALL":
            if len(pending_calls) >= instr.arg:
                args = pending_calls[-instr.arg:]
                for arg in args:
                    if arg in const_assignments:
                        val = const_assignments[arg]
                        if isinstance(val, int):
                            pipeline.append(f"XOR with constant {val}")
                pending_calls = pending_calls[:-instr.arg]

        elif instr.opname == "LOAD_ATTR" and instr.argval == "fromhex":
            pipeline.append("Hex decode via fromhex")

        elif instr.opname == "LOAD_GLOBAL" and instr.argval == "exec":
            exec_triggered = True
            pipeline.append("Exec of decoded payload")

    for i in range(len(instructions) - 2):
        if (instructions[i].opname == "LOAD_CONST" and instructions[i].argval is None and
            instructions[i+1].opname == "LOAD_CONST" and instructions[i+1].argval == -1 and
            instructions[i+2].opname == "BUILD_SLICE"):
            print("[*] Detected reverse slice pattern [::-1] via LOAD_CONST/BUILD_SLICE sequence")
            pipeline.append("Reverse via [::-1]")
            break

    for const in code_obj.co_consts:
        if isinstance(const, CodeType):
            try:
                list(dis.get_instructions(const))
                sub_pipeline = find_decode_pipeline(const)
                for step in sub_pipeline:
                    if step not in pipeline:
                        pipeline.append(step)
            except Exception as e:
                print(f"[!] Skipping broken nested code object in pipeline: {e}")
                continue

    return pipeline

def find_potential_xor_operations(code_obj, path=""):
    try:
        instructions = list(dis.get_instructions(code_obj))
    except Exception as e:
        print(f"[!] Skipping disassembly in {path}: {e}")
        return set(), []

    potential_keys = set()
    decoding_patterns = []

    for i, instr in enumerate(instructions):
        if instr.opname in {"BINARY_XOR", "INPLACE_XOR"}:
            prev_instrs = instructions[max(0, i - 3):i]
            key_guess = "(unknown)"

            for prev in reversed(prev_instrs):
                if prev.opname == "LOAD_CONST":
                    key_guess = prev.argval
                    potential_keys.add(key_guess)
                    break
                elif prev.opname in {"LOAD_FAST", "LOAD_GLOBAL", "LOAD_DEREF"}:
                    key_guess = f"(variable: {prev.argval})"
                    break

            decoding_patterns.append({
                "index": i,
                "offset": instr.offset,
                "key_guess": key_guess,
                "context": path or "<module>",
                "opname": instr.opname,
            })

    for const in code_obj.co_consts:
        if isinstance(const, CodeType):
            try:
                list(dis.get_instructions(const))
            except Exception as e:
                print(f"[!] Skipping broken nested code object in {path}: {e}")
                continue
            sub_path = f"{path}->{const.co_name}" if path else const.co_name
            sub_keys, sub_patterns = find_potential_xor_operations(const, sub_path)
            potential_keys.update(sub_keys)
            decoding_patterns.extend(sub_patterns)

    return potential_keys, decoding_patterns

def find_encoded_strings(code_obj, path=""):
    encoded_strings = []

    for const in code_obj.co_consts:
        if isinstance(const, str):
            if is_hex_string(const):
                encoded_strings.append((path or "<module>", 'hex', const))
            elif is_base64_string(const):
                encoded_strings.append((path or "<module>", 'base64', const))
        elif isinstance(const, (bytes, bytearray)):
            if is_suspicious_bytes(const):
                #sig = detect_binary_blob_signature(const)
                magic_type = detect_magic_type(const)
                preview = const[:32].hex() + ("..." if len(const) > 32 else "")
                #desc = sig if sig else "Large binary blob"
                encoded_strings.append((path or "<module>", f"bytes ({magic_type})", preview))
        elif isinstance(const, CodeType):
            sub_path = f"{path}->{const.co_name}" if path else const.co_name
            encoded_strings.extend(find_encoded_strings(const, sub_path))

    return encoded_strings


def find_decompression_and_reverse_usage(code_obj, path=""):
    try:
        instructions = list(dis.get_instructions(code_obj))
    except Exception as e:
        print(f"[!] Skipping decoding scan in {path}: {e}")
        return []

    patterns = []
    crypto_keywords = {
        "AES": "AES decryption",
        "RC4": "RC4 decryption",
        "ARC4": "RC4 decryption",
        "ROT": "ROT cipher",
        "DES": "DES decryption",
        "Blowfish": "Blowfish decryption",
        "ChaCha": "ChaCha encryption/decryption",
        "decode": "Generic decode call",
        "decompress": "Zlib decompress",
        "b64decode": "Base64 decode",
        "unhexlify": "Hex decode",
        "bytes": "Byte casting",
        "reversed": "Reverse iterator"
    }

    for i, instr in enumerate(instructions):
        for op in ["LOAD_ATTR", "LOAD_GLOBAL", "LOAD_NAME"]:
            if instr.opname == op and isinstance(instr.argval, str):
                for key, label in crypto_keywords.items():
                    if key.lower() in instr.argval.lower():
                        patterns.append((path or "<module>", f"{label} via {instr.argval}", instr.offset))

        if instr.opname == "BUILD_SLICE":
            slice_instrs = instructions[max(0, i - 2):i + 1]
            slice_args = [s.argval for s in slice_instrs if s.opname == "LOAD_CONST"]
            if len(slice_args) == 2 and slice_args[0] is None and slice_args[1] == -1:
                patterns.append((path or "<module>", "Reverse slice [::-1]", instr.offset))

    for const in code_obj.co_consts:
        if isinstance(const, CodeType):
            try:
                list(dis.get_instructions(const))
                sub_path = f"{path}->{const.co_name}" if path else const.co_name
                patterns.extend(find_decompression_and_reverse_usage(const, sub_path))
            except Exception as e:
                print(f"[!] Skipping nested function in {path}: {e}")
                continue

    return patterns


def extract_all_constants(code_obj):
    found = []
    def recurse(obj):
        for const in getattr(obj, 'co_consts', []):
            found.append(const)
            if isinstance(const, CodeType):
                recurse(const)
    recurse(code_obj)
    return found

def suggest_decoding_order(keys, encoded_strings, funcs, pipeline, code_obj):
    found_steps = set(pipeline)

    if any("Reverse" in f[1] for f in funcs) and "Reverse via [::-1]" not in found_steps:
        pipeline.append("Reverse via [::-1]")
    if any("b64decode" in f[1] for f in funcs) and "Base64 decode via b64decode" not in found_steps:
        pipeline.append("Base64 decode via b64decode")
    if any("decompress" in f[1] for f in funcs) and "Zlib decompress via decompress" not in found_steps:
        pipeline.append("Zlib decompress via decompress")
    if any("bytes" in typ for _, typ, _ in encoded_strings):
	    if all("decompress" not in step for step in pipeline):
		    pipeline.append("Possibly decompress or decrypt binary blob")

    all_consts = extract_all_constants(code_obj)
    if 157 in all_consts and all("XOR" not in step for step in pipeline):
        print("[*] Heuristic: Found constant 157 — likely XOR key")
        pipeline.append("XOR with constant 157")
    if any(isinstance(c, slice) and c == slice(None, None, -1) for c in all_consts) and "Reverse via [::-1]" not in pipeline:
        print("[*] Heuristic: Found slice(None, None, -1) — likely reverse operation")
        pipeline.append("Reverse via [::-1]")
    if any(isinstance(c, str) and "zlib" in c for c in all_consts) and all("decompress" not in step for step in pipeline):
        print("[*] Heuristic: Found 'zlib' in string — may indicate compression")
        pipeline.append("Zlib decompress via decompress")
    if any(isinstance(c, str) and is_base64_string(c) for c in all_consts) and all("b64decode" not in step for step in pipeline):
        print("[*] Heuristic: Found base64-like string — likely base64 encoded")
        pipeline.append("Base64 decode via b64decode")
    crypto_terms = ["AES", "RC4", "ARC4", "DES", "Blowfish", "ChaCha", "ROT"]
    for term in crypto_terms:
        if any(isinstance(c, str) and term.lower() in c.lower() for c in all_consts):
            label = f"{term} (based on string match)"
            if all(term not in step for step in pipeline):
                print(f"[*] Heuristic: Found string indicating {label}")
                pipeline.append(f"{label}")

    print("[*] Suggested decoding flow:")
    if pipeline:
        for step in pipeline:
            print(f"  - {step}")
    else:
        if encoded_strings:
            print("  1. Decode encoded strings (base64 or hex)")
        if any("decompress" in func[1] for func in funcs):
            print("  2. Apply decompression (e.g., zlib, gzip, bz2)")
        if any("Reverse" in func[1] or "reversed" in func[1] for func in funcs):
            print("  3. Reverse bytes or apply [::-1] slice")
        if keys:
            print("  4. XOR decrypt with key(s)")
    print()

def analyze_file(pyc_path):
    try:
        version = detect_python_version(pyc_path)
        print(f"[*] Detected .pyc magic version: {version}")
        with open(pyc_path, "rb") as f:
            f.read(PYTHON_MAGIC_SIZE)  # Skip header
            code_obj = marshal.load(f)
    except Exception as e:
        print(f"[!] Failed to load .pyc file: {e}")
        sys.exit(1)

    print(f"[*] Analyzing: {pyc_path}")
    print("[*] Searching for XOR and decoding structures...\n")

    keys, patterns = find_potential_xor_operations(code_obj)
    encoded_strings = find_encoded_strings(code_obj)
    funcs = find_decompression_and_reverse_usage(code_obj)
    pipeline = find_decode_pipeline(code_obj)
    cipher_heuristics = find_cipher_mentions(code_obj)
    if cipher_heuristics:
	    print("[+] Cipher Heuristics Detected:")
	    for ctx, desc in cipher_heuristics:
		    print(f"  - {desc} in {ctx}")
	    print()

    if keys or patterns:
        print(f"[+] Potential XOR keys found: {keys}\n")
        print("[+] XOR decoding patterns:")
        for pat in patterns:
            print(f"  - In {pat['context']} @ offset {pat['offset']}: {pat['opname']} with key guess {pat['key_guess']!r}")
        print()

    if encoded_strings:
        print("[+] Encoded strings detected:")
        for ctx, typ, val in encoded_strings:
            preview = val[:60] + ("..." if len(val) > 60 else "")
            print(f"  - {typ} in {ctx}: {preview}")
        print()

    if funcs:
        print("[+] Possible decoding/reversing operations:")
        for ctx, desc, offset in funcs:
            print(f"  - {desc} @ offset {offset} in {ctx}")
        print()

    suggest_decoding_order(keys, encoded_strings, funcs, pipeline, code_obj)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python pyc_analyzer.py <pyc_file>")
        sys.exit(1)
    analyze_file(sys.argv[1])
