import subprocess
import sys
from typing import NamedTuple

class ExecutionResult(NamedTuple):
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

def run_safe_command(cmd_args: list[str], timeout: int = 10) -> ExecutionResult:
    """
    Executes CLI binaries safely without invoking shell interpreters.
    
    Args:
        cmd_args: List vector where index 0 is binary and remaining elements are arguments.
        timeout: Maximum execution duration in seconds.
    """
    # Defensive check: ensure cmd_args is a list vector
    if not isinstance(cmd_args, list) or not cmd_args:
        raise ValueError("Command must be supplied as a non-empty list of arguments.")

    print(f"[*] Executing: {' '.join(cmd_args)}", file=sys.stderr)

    try:
        # shell=False prevents shell metasymbol interpretation (| ; && $ () `)
        # stdin=subprocess.DEVNULL prevents hanging on interactive commands like openssl
        process = subprocess.run(
            cmd_args,
            stdin=subprocess.DEVNULL,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        return ExecutionResult(
            returncode=process.returncode,
            stdout=process.stdout,
            stderr=process.stderr,
            timed_out=False
        )
    except subprocess.TimeoutExpired:
        print(f"[!] Timeout of {timeout}s exceeded for: {cmd_args[0]}", file=sys.stderr)
        return ExecutionResult(
            returncode=-1,
            stdout="",
            stderr=f"Execution timed out after {timeout} seconds.",
            timed_out=True
        )
    except FileNotFoundError:
        print(f"[!] Binary not found: {cmd_args[0]}", file=sys.stderr)
        return ExecutionResult(
            returncode=-1,
            stdout="",
            stderr=f"System binary '{cmd_args[0]}' was not found in host PATH.",
            timed_out=False
        )
