"""Near-real-time polling monitor: watches approved local log files only."""
import time
from pathlib import Path
from scripts.analyze_windows_logs import main as analyze_windows


def watch(path="logs/windows_security_events.csv", interval=5, once=False):
    target = Path(path)
    interval = max(1, min(int(interval), 300))
    last_signature = None
    while True:
        try:
            stat = target.stat()
            signature = (stat.st_mtime_ns, stat.st_size)
            if signature != last_signature:
                analyze_windows()
                last_signature = signature
        except FileNotFoundError:
            pass
        if once:
            return
        time.sleep(interval)
