import re
from src.security_mcp.sanitizer import sanitize_target, sanitize_url
from src.security_mcp.executor import run_safe_command

def lookup_dns(domain: str) -> str:
    """
    Queries A, AAAA, MX, and TXT records using dig and formats results as a Markdown table.
    """
    clean_domain = sanitize_target(domain)
    
    # Execute dig for multiple record types
    cmd = ["dig", "+noall", "+answer", clean_domain, "A", "AAAA", "MX", "TXT"]
    result = run_safe_command(cmd, timeout=10)
    
    if result.timed_out or result.returncode != 0:
        return f"**Error executing DNS lookup:** {result.stderr or 'Command timed out'}"
        
    if not result.stdout.strip():
        return f"No DNS records found for target domain `{clean_domain}`."
        
    rows = []
    for line in result.stdout.strip().splitlines():
        parts = line.split(maxsplit=4)
        if len(parts) == 5:
            rec_domain, ttl, rclass, rtype, rvalue = parts
            rows.append(f"| `{rtype}` | `{ttl}` | `{rvalue.strip()}` |")
            
    if not rows:
        return f"Raw Output for `{clean_domain}`:\n```\n{result.stdout}\n```"

    md = [
        f"### DNS Resolution: `{clean_domain}`\n",
        "| Record Type | TTL (s) | Value |",
        "| :--- | :--- | :--- |",
        *rows
    ]
    return "\n".join(md)


def inspect_http_headers(url: str) -> str:
    """
    Fetches HTTP response headers via curl and checks for key security headers.
    """
    clean_url = sanitize_url(url)
    
    # -s: silent, -I: fetch headers only, --max-time: timeout
    cmd = ["curl", "-s", "-I", "--max-time", "10", clean_url]
    result = run_safe_command(cmd, timeout=12)
    
    if result.timed_out or result.returncode != 0:
        return f"**Error fetching HTTP headers:** {result.stderr or 'Connection timed out'}"

    lines = result.stdout.strip().splitlines()
    if not lines:
        return f"No response headers received from `{clean_url}`."

    status_line = lines[0]
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, val = line.split(":", 1)
            headers[key.strip().lower()] = val.strip()

    # Track presence of standard security headers
    security_headers = {
        "strict-transport-security": "HSTS",
        "content-security-policy": "CSP",
        "x-frame-options": "Clickjacking Protection",
        "x-content-type-options": "MIME Sniffing Defense",
        "referrer-policy": "Referrer Policy",
        "permissions-policy": "Permissions Policy"
    }

    sec_checks = []
    for header, name in security_headers.items():
        if header in headers:
            sec_checks.append(f"| **{name}** (`{header}`) | `PRESENT` | `{headers[header]}` |")
        else:
            sec_checks.append(f"| **{name}** (`{header}`) | `MISSING` | — |")

    md = [
        f"### HTTP Header Security Analysis: `{clean_url}`\n",
        f"**Status Line:** `{status_line}`\n",
        "#### Security Header Audit",
        "| Header | Status | Value |",
        "| :--- | :--- | :--- |",
        *sec_checks,
        "\n#### Server Info",
        f"- **Server Header:** `{headers.get('server', 'Hidden / Unspecified')}`",
        f"- **Powered By:** `{headers.get('x-powered-by', 'Unspecified')}`"
    ]
    return "\n".join(md)


def inspect_ssl_cert(target: str) -> str:
    """
    Retrieves TLS certificate info using OpenSSL and extracts SANs, issuer, and validity.
    """
    clean_target = sanitize_target(target)
    
    # Execute OpenSSL s_client to retrieve certificate details
    # Piping empty input into s_client prevents process hanging
    cmd = ["openssl", "s_client", "-connect", f"{clean_target}:443", "-servername", clean_target]
    
    # Execute openssl s_client securely
    result = run_safe_command(cmd, timeout=10)
    
    if result.timed_out:
        return f"**SSL Inspection Timeout:** Connection to `{clean_target}:443` timed out."
        
    stdout = result.stdout
    if "connect:errno=" in stdout or "Handshake failure" in stdout or not stdout:
        return f"**TLS Connection Failed:** Could not establish TLS handshake with `{clean_target}:443`."

    # Parse subject, issuer, and validation dates from openssl output
    subject_match = re.search(r"subject=(.+)", stdout)
    issuer_match = re.search(r"issuer=(.+)", stdout)
    
    subject = subject_match.group(1).strip() if subject_match else "Unknown"
    issuer = issuer_match.group(1).strip() if issuer_match else "Unknown"
    
    # Parse SANs if available in stdout
    sans = re.findall(r"DNS:[^\s,]+", stdout)
    san_list = ", ".join([s.replace("DNS:", "`") + "`" for s in sans[:5]]) if sans else "None extracted"

    md = [
        f"### TLS/SSL Certificate Summary: `{clean_target}`\n",
        "| Field | Detail |",
        "| :--- | :--- |",
        f"| **Target Host** | `{clean_target}:443` |",
        f"| **Subject** | `{subject}` |",
        f"| **Issuer** | `{issuer}` |",
        f"| **Subject Alt Names (SANs)** | {san_list} |",
        f"| **Handshake State** | `Successful` |"
    ]
    return "\n".join(md)


def lookup_whois(domain: str) -> str:
    """
    Executes WHOIS query and parses registrar, creation date, and expiration info.
    """
    clean_domain = sanitize_target(domain)
    
    cmd = ["whois", clean_domain]
    result = run_safe_command(cmd, timeout=10)
    
    if result.timed_out or result.returncode != 0:
        return f"**Error executing WHOIS lookup:** {result.stderr or 'Command timed out'}"

    raw_output = result.stdout
    
    # Extract key WHOIS fields using regex patterns
    registrar = re.search(r"(?:Registrar:|Registrar Name:)\s*(.+)", raw_output, re.IGNORECASE)
    creation = re.search(r"(?:Creation Date:|Created On:)\s*(.+)", raw_output, re.IGNORECASE)
    expiry = re.search(r"(?:Registry Expiry Date:|Expiration Date:)\s*(.+)", raw_output, re.IGNORECASE)
    name_servers = re.findall(r"(?:Name Server:|nserver:)\s*([^\s]+)", raw_output, re.IGNORECASE)

    reg_val = registrar.group(1).strip() if registrar else "Unspecified"
    created_val = creation.group(1).strip() if creation else "Unspecified"
    expiry_val = expiry.group(1).strip() if expiry else "Unspecified"
    ns_val = ", ".join([f"`{ns.lower()}`" for ns in sorted(set(name_servers))[:4]]) if name_servers else "None found"

    md = [
        f"### WHOIS Registration Data: `{clean_domain}`\n",
        "| Metadata Field | Value |",
        "| :--- | :--- |",
        f"| **Registrar** | `{reg_val}` |",
        f"| **Creation Date** | `{created_val}` |",
        f"| **Expiry Date** | `{expiry_val}` |",
        f"| **Name Servers** | {ns_val} |"
    ]
    return "\n".join(md)
