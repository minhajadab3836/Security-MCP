from unittest.mock import patch
import pytest

from security_mcp.executor import ExecutionResult
from security_mcp.tools import (
    lookup_dns,
    inspect_http_headers,
    inspect_ssl_cert,
    lookup_whois,
)


class TestLookupDns:
    def test_lookup_dns_valid_output(self):
        mock_stdout = (
            "example.com.\t300\tIN\tA\t93.184.215.14\n"
            "example.com.\t300\tIN\tTXT\t\"v=spf1 -all\"\n"
        )
        with patch("security_mcp.tools.run_safe_command", return_value=ExecutionResult(0, mock_stdout, "")):
            result = lookup_dns("example.com")
            assert "### DNS Resolution: `example.com`" in result
            assert "`A`" in result
            assert "`93.184.215.14`" in result
            assert "`TXT`" in result

    def test_lookup_dns_empty_records(self):
        with patch("security_mcp.tools.run_safe_command", return_value=ExecutionResult(0, "", "")):
            result = lookup_dns("example.com")
            assert "No DNS records found for target domain `example.com`." in result

    def test_lookup_dns_command_failure(self):
        with patch("security_mcp.tools.run_safe_command", return_value=ExecutionResult(1, "", "Connection refused")):
            result = lookup_dns("example.com")
            assert "**Error executing DNS lookup:**" in result

    def test_lookup_dns_invalid_domain_raises(self):
        with pytest.raises(ValueError):
            lookup_dns("example.com; rm -rf /")


class TestInspectHttpHeaders:
    def test_inspect_http_headers_success(self):
        mock_headers = (
            "HTTP/2 200 OK\r\n"
            "strict-transport-security: max-age=31536000; includeSubDomains\r\n"
            "content-security-policy: default-src 'self'\r\n"
            "x-frame-options: DENY\r\n"
            "x-content-type-options: nosniff\r\n"
            "server: cloudflare\r\n"
        )
        with patch("security_mcp.tools.run_safe_command", return_value=ExecutionResult(0, mock_headers, "")):
            result = inspect_http_headers("https://example.com")
            assert "### HTTP Header Security Analysis: `https://example.com`" in result
            assert "**Status Line:** `HTTP/2 200 OK`" in result
            assert "**HSTS** (`strict-transport-security`) | `PRESENT`" in result
            assert "**CSP** (`content-security-policy`) | `PRESENT`" in result
            assert "**Clickjacking Protection** (`x-frame-options`) | `PRESENT`" in result
            assert "**MIME Sniffing Defense** (`x-content-type-options`) | `PRESENT`" in result
            assert "- **Server Header:** `cloudflare`" in result

    def test_inspect_http_headers_missing_headers(self):
        mock_headers = "HTTP/1.1 200 OK\r\nserver: Apache\r\n"
        with patch("security_mcp.tools.run_safe_command", return_value=ExecutionResult(0, mock_headers, "")):
            result = inspect_http_headers("http://example.com")
            assert "**HSTS** (`strict-transport-security`) | `MISSING`" in result
            assert "**CSP** (`content-security-policy`) | `MISSING`" in result

    def test_inspect_http_headers_failure(self):
        with patch("security_mcp.tools.run_safe_command", return_value=ExecutionResult(7, "", "Failed to connect")):
            result = inspect_http_headers("http://example.com")
            assert "**Error fetching HTTP headers:**" in result

    def test_inspect_http_headers_invalid_url_raises(self):
        with pytest.raises(ValueError):
            inspect_http_headers("ftp://example.com")


class TestInspectSslCert:
    def test_inspect_ssl_cert_success(self):
        mock_stdout = (
            "CONNECTED(00000003)\n"
            "depth=2 C = US, O = Internet Security Research Group, CN = ISRG Root X1\n"
            "certificate:\n"
            "subject=CN = example.com\n"
            "issuer=C = US, O = Let's Encrypt, CN = R3\n"
            "DNS:example.com, DNS:www.example.com\n"
        )
        with patch("security_mcp.tools.run_safe_command", return_value=ExecutionResult(0, mock_stdout, "")):
            result = inspect_ssl_cert("example.com")
            assert "### TLS/SSL Certificate Summary: `example.com`" in result
            assert "CN = example.com" in result
            assert "Let's Encrypt" in result
            assert "**Handshake State** | `Successful`" in result

    def test_inspect_ssl_cert_connection_failed(self):
        mock_stdout = "connect:errno=111\n"
        with patch("security_mcp.tools.run_safe_command", return_value=ExecutionResult(1, mock_stdout, "")):
            result = inspect_ssl_cert("scanme.nmap.org")
            assert "**TLS Connection Failed:**" in result

    def test_inspect_ssl_cert_timeout(self):
        with patch("security_mcp.tools.run_safe_command", return_value=ExecutionResult(-1, "", "timed out", timed_out=True)):
            result = inspect_ssl_cert("example.com")
            assert "**SSL Inspection Timeout:**" in result

    def test_inspect_ssl_cert_invalid_target_raises(self):
        with pytest.raises(ValueError):
            inspect_ssl_cert("example.com; rm -rf /")


class TestLookupWhois:
    def test_lookup_whois_success(self):
        mock_stdout = (
            "Domain Name: example.com\n"
            "Registrar: RESERVED-Internet Assigned Numbers Authority\n"
            "Creation Date: 1995-08-14T04:00:00Z\n"
            "Registry Expiry Date: 2027-08-13T04:00:00Z\n"
            "Name Server: a.iana-servers.net\n"
            "Name Server: b.iana-servers.net\n"
        )
        with patch("security_mcp.tools.run_safe_command", return_value=ExecutionResult(0, mock_stdout, "")):
            result = lookup_whois("example.com")
            assert "### WHOIS Registration Data: `example.com`" in result
            assert "RESERVED-Internet Assigned Numbers Authority" in result
            assert "1995-08-14T04:00:00Z" in result
            assert "2027-08-13T04:00:00Z" in result
            assert "`a.iana-servers.net`" in result

    def test_lookup_whois_failure(self):
        with patch("security_mcp.tools.run_safe_command", return_value=ExecutionResult(1, "", "Lookup failed")):
            result = lookup_whois("example.com")
            assert "**Error executing WHOIS lookup:**" in result

    def test_lookup_whois_invalid_domain_raises(self):
        with pytest.raises(ValueError):
            lookup_whois("-o /tmp/file")
