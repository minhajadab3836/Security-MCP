import shutil
import sys

REQUIRED_TOOLS = ["dig", "curl", "whois", "openssl"]

def verify_environment() -> bool:
    # All setup logs MUST route to stderr to avoid corrupting stdout stdio transport
    print("[*] Auditing host CLI security utilities...", file=sys.stderr)
    missing = []
    
    for tool in REQUIRED_TOOLS:
        binary_path = shutil.which(tool)
        if binary_path:
            print(f"  [✓] {tool} -> {binary_path}", file=sys.stderr)
        else:
            print(f"  [✗] {tool} NOT FOUND in PATH", file=sys.stderr)
            missing.append(tool)
            
    if missing:
        print(f"[!] Error: Missing dependencies: {', '.join(missing)}", file=sys.stderr)
        return False
        
    print("[✓] Environment check passed. Stdio isolated correctly.", file=sys.stderr)
    return True

if __name__ == "__main__":
    if not verify_environment():
        sys.exit(1)
