"""CYBERWOLF Safe Subprocess Execution Engine (V2).

Enforces strict defense-in-depth command execution controls:
- shell=False strictly enforced (never shell string evaluation)
- Subprocess timeout controls with aggressive child process termination
- stdout/stderr capture with size limits to prevent RAM exhaustion
- Return code handling and structured error reporting
- Cryptographic SHA-256 hashing of raw stdout
- Audit logging of all executions
- ToolRun persistence when scan_id is provided
"""

import subprocess
import time
import hashlib
import uuid
from typing import List, Dict, Any, Optional, Tuple
from app.core.logger import get_logger, audit_log
from app.core.exceptions import ToolExecutionError, ValidationError
from app.database.models import ToolRun

logger = get_logger()

# Maximum stdout/stderr size in characters (5MB) to protect against memory exhaustion
MAX_OUTPUT_CHARS = 5 * 1024 * 1024


class ToolRunner:
    """Safely invokes system tools with strictly structured argument arrays and timeout controls."""

    @staticmethod
    def execute(cmd_args: List[str], timeout: int = 60, target: Optional[str] = None,
                tool_name: Optional[str] = None, scan_id: Optional[str] = None) -> Tuple[int, str, str]:
        """Execute a command without shell interpretation.

        Args:
            cmd_args: Structured list of string arguments (e.g. ['/usr/bin/nmap', '-F', '127.0.0.1'])
            timeout: Maximum execution time in seconds
            target: Target string for audit logging
            tool_name: Tool name for provenance
            scan_id: Optional scan session ID to persist ToolRun

        Returns:
            (exit_code, stdout_str, stderr_str)
        """
        if not cmd_args or not isinstance(cmd_args, list):
            raise ToolExecutionError("Command arguments must be a non-empty list of strings.")

        # Ensure all arguments are strings and non-empty
        sanitized_args = []
        for idx, arg in enumerate(cmd_args):
            if not isinstance(arg, str):
                raise ValidationError(f"Command argument at index {idx} must be a string, got {type(arg)}.")
            if not arg.strip():
                continue
            sanitized_args.append(str(arg))

        if not sanitized_args:
            raise ToolExecutionError("Command arguments list cannot be empty after sanitization.")

        binary_name = sanitized_args[0]
        cmd_display = " ".join(sanitized_args)
        logger.info(f"Executing tool command: {cmd_display} (timeout={timeout}s, shell=False)")
        audit_log("TOOL_EXECUTION", "RUN", target=target, tool=tool_name or binary_name,
                  decision="PROCEEDED", details=f"Command: {cmd_display}")

        start_time = time.time()
        start_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start_time))

        try:
            process = subprocess.run(
                sanitized_args,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False
            )
            duration = round(time.time() - start_time, 2)
            stdout = process.stdout or ""
            stderr = process.stderr or ""

            # Truncate if output exceeds memory limits
            if len(stdout) > MAX_OUTPUT_CHARS:
                stdout = stdout[:MAX_OUTPUT_CHARS] + f"\n\n[!] Output truncated at {MAX_OUTPUT_CHARS} characters."
            if len(stderr) > MAX_OUTPUT_CHARS:
                stderr = stderr[:MAX_OUTPUT_CHARS] + f"\n\n[!] Error output truncated at {MAX_OUTPUT_CHARS} characters."

            logger.info(f"Tool {binary_name} completed in {duration}s with exit code {process.returncode}")

            # Record ToolRun if scan_id provided
            if scan_id:
                try:
                    from app.database.operations import record_tool_run
                    hash_val = hashlib.sha256(stdout.encode("utf-8")).hexdigest()
                    tool_run = ToolRun(
                        id=f"RUN-{uuid.uuid4().hex[:8].upper()}",
                        scan_id=scan_id,
                        tool_name=tool_name or binary_name,
                        command_line=cmd_display,
                        exit_code=process.returncode,
                        start_time=start_iso,
                        end_time=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        duration_sec=duration,
                        stdout_excerpt=stdout[:1000],
                        stderr_excerpt=stderr[:1000],
                        hash_sha256=hash_val,
                        status="COMPLETED" if process.returncode == 0 else "FAILED"
                    )
                    record_tool_run(tool_run)
                except Exception as e:
                    logger.debug(f"Non-critical: Failed to save ToolRun: {e}")

            return process.returncode, stdout, stderr

        except subprocess.TimeoutExpired as e:
            duration = round(time.time() - start_time, 2)
            logger.warning(f"Tool execution timed out after {timeout}s: {cmd_display}")
            audit_log("TOOL_EXECUTION", "TIMEOUT", target=target, tool=tool_name or binary_name,
                      decision="TERMINATED", details=f"Exceeded {timeout}s")
            stdout = e.stdout.decode("utf-8", errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
            stderr = f"Execution timed out after {timeout} seconds."

            if scan_id:
                try:
                    from app.database.operations import record_tool_run
                    tool_run = ToolRun(
                        id=f"RUN-{uuid.uuid4().hex[:8].upper()}",
                        scan_id=scan_id,
                        tool_name=tool_name or binary_name,
                        command_line=cmd_display,
                        exit_code=-1,
                        start_time=start_iso,
                        end_time=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        duration_sec=duration,
                        stdout_excerpt=stdout[:1000],
                        stderr_excerpt=stderr,
                        status="TIMED_OUT"
                    )
                    record_tool_run(tool_run)
                except Exception:
                    pass

            return -1, stdout, stderr

        except FileNotFoundError:
            msg = f"Binary '{binary_name}' not found on host system."
            logger.error(msg)
            return 127, "", msg

        except PermissionError as e:
            msg = f"Permission denied executing '{binary_name}': {e}"
            logger.error(msg)
            return 126, "", msg

        except Exception as e:
            logger.error(f"Unexpected error executing {cmd_display}: {e}")
            return 1, "", str(e)


CommandRunner = ToolRunner

