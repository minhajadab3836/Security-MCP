import subprocess
from unittest.mock import patch
import pytest

from security_mcp.executor import run_safe_command, ExecutionResult


class TestRunSafeCommand:
    def test_successful_execution(self):
        result = run_safe_command(["echo", "security_test"])
        assert isinstance(result, ExecutionResult)
        assert result.returncode == 0
        assert result.stdout.strip() == "security_test"
        assert not result.timed_out

    def test_shell_metasymbols_are_not_evaluated(self):
        # Shell metasymbols like ; should NOT split commands because shell=False
        result = run_safe_command(["echo", "safe; cat /etc/passwd"])
        assert result.returncode == 0
        assert result.stdout.strip() == "safe; cat /etc/passwd"

    @pytest.mark.parametrize("invalid_args", [None, [], "echo hello", 123])
    def test_invalid_command_arguments(self, invalid_args):
        with pytest.raises(ValueError, match="Command must be supplied as a non-empty list"):
            run_safe_command(invalid_args)  # type: ignore

    def test_binary_not_found(self):
        result = run_safe_command(["__non_existent_binary_xyz_123__", "arg"])
        assert result.returncode == -1
        assert "not found" in result.stderr
        assert not result.timed_out

    def test_command_timeout(self):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["sleep", "10"], timeout=1)):
            result = run_safe_command(["sleep", "10"], timeout=1)
            assert result.timed_out is True
            assert result.returncode == -1
            assert "timed out" in result.stderr

    def test_non_zero_exit_code(self):
        result = run_safe_command(["ls", "/path/that/does/not/exist/98765"])
        assert result.returncode != 0
        assert not result.timed_out
