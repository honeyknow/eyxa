# Eyxa EDR

## Security & Reliability Caveats

> [!CAUTION]
> **Remote Command Execution (RCE) Surface**
> This agent implements an unrestricted `run_command` response action feature. A compromised backend server or stolen agent token grants full, unauthenticated Remote Command Execution (RCE) as `NT AUTHORITY\SYSTEM` (or the user the agent is running as) across all enrolled endpoints.
> 
> **Reliability & Execution Hang Risk**
> Commands executed via `run_command` have **no execution timeout** and **no output-size cap**. 
> - If a spawned command hangs or prompts for interactive input (e.g., `pause`), it will block the agent's command-execution thread indefinitely.
> - An indefinitely blocked thread prevents any further response actions (like `kill_process`) from executing until the agent process is manually restarted.
> - Massive output could theoretically cause unbounded memory allocation, though the OS virtual memory limit is the only boundary.
