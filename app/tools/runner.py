"""CYBERWOLF Safe Subprocess Execution Engine."""

import subprocess
import time
from typing import List, Dict, Any, Optional, Tuple
from app.core.logger import get_logger, audit_log
from app.core.exceptions import ToolExecutionError

logger = get_logger()

class ToolRunner:
    """Safely invokes system tools with strictly structured argument arrays and timeout controls."""
    
    @staticmethod
    def execute(cmd_args: List[str], timeout: int = 60, target: Optional[str] = None,
                tool_name: Optional[str] = None) -> Tuple[int, str, str]:
        """Execute a command without shell interpretation.
        
        Returns:
            (exit_code, stdout_str, stderr_str)
        """
        if not cmd_args or not isinstance(cmd_args, list):
            raise ToolExecutionError("Command arguments must be a non-empty list of strings.")

        cmd_display = " ".join(cmd_args)
        logger.info(f"Executing tool command: {cmd_display} (timeout={timeout}s)")
        audit_log("TOOL_EXECUTION", "RUN", target=target, tool=tool_name or cmd_args[0],
                  decision="PROCEEDED", details=f"Command: {cmd_display}")

        start_time = time.time()
        try:
            process = subprocess.run(
                cmd_args,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False
            )
            duration = round(time.time() - start_time, 2)
            logger.info(f"Tool {cmd_args[0]} completed in {duration}s with exit code {process.returncode}")
            return process.returncode, process.stdout, process.stderr
        except subprocess.TimeoutExpired as e:
            logger.warning(f"Tool execution timed out after {timeout}s: {cmd_display}")
            stdout = e.stdout.decode("utf-8", errors="replace") if e.stdout else ""
            stderr = f"Execution timed out after {timeout} seconds."
            return -1, stdout, stderr
        except FileNotFoundError:
            msg = f"Binary '{cmd_args[0]}' not found on host."
            logger.error(msg)
            return 127, "", msg
        except Exception as e:
            logger.error(f"Unexpected error executing {cmd_display}: {e}")
            return 1, "", str(e)
