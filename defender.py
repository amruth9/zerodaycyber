import argparse
import math
import os
import queue
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:  # pragma: no cover - fallback when watchdog isn't installed
    FileSystemEventHandler = object
    Observer = None

try:
    import psutil
except ImportError:  # pragma: no cover - fallback when psutil isn't installed
    psutil = None

SUSPICIOUS_EXTENSIONS = {
    ".locked",
    ".encrypted",
    ".crypt",
    ".crypto",
    ".locky",
    ".zepto",
    ".cerber",
}


@dataclass
class DefenderConfig:
    folder: Path
    burst_threshold: int = 25
    burst_window_seconds: int = 10
    entropy_threshold: float = 7.2
    entropy_sample_bytes: int = 256 * 1024
    whitelist_processes: Set[str] = field(default_factory=lambda: {"explorer.exe"})
    deny_write_on_alert: bool = True


@dataclass
class FileEvent:
    path: Path
    event_type: str
    timestamp: float


class RansomwareDefender:
    def __init__(self, config: DefenderConfig) -> None:
        self.config = config
        self.events: "queue.Queue[FileEvent]" = queue.Queue()
        self.recent_events: List[FileEvent] = []
        self.stop_event = threading.Event()

    def start(self) -> None:
        if Observer is None:
            print("watchdog is not installed; falling back to polling.")
            self._polling_loop()
            return

        observer = Observer()
        observer.schedule(WatchdogHandler(self.events), str(self.config.folder), recursive=True)
        observer.start()
        print(f"Monitoring {self.config.folder} for ransomware behavior...")
        try:
            self._process_loop()
        finally:
            observer.stop()
            observer.join()

    def _polling_loop(self) -> None:
        print(f"Polling {self.config.folder} for ransomware behavior...")
        snapshot = self._snapshot_files()
        while not self.stop_event.is_set():
            time.sleep(1)
            new_snapshot = self._snapshot_files()
            changes = self._diff_snapshots(snapshot, new_snapshot)
            for path, event_type in changes:
                self.events.put(FileEvent(path=path, event_type=event_type, timestamp=time.time()))
            snapshot = new_snapshot
            self._process_events()

    def _process_loop(self) -> None:
        while not self.stop_event.is_set():
            self._process_events()
            time.sleep(0.25)

    def _process_events(self) -> None:
        while not self.events.empty():
            event = self.events.get()
            self._record_event(event)
            if self._is_suspicious(event.path):
                self._trigger_alert(reason=f"Suspicious file change detected: {event.path}")
                continue
            if self._is_burst():
                self._trigger_alert(reason="High-volume file changes detected")

    def _record_event(self, event: FileEvent) -> None:
        self.recent_events.append(event)
        cutoff = time.time() - self.config.burst_window_seconds
        self.recent_events = [e for e in self.recent_events if e.timestamp >= cutoff]

    def _is_burst(self) -> bool:
        return len(self.recent_events) >= self.config.burst_threshold

    def _is_suspicious(self, path: Path) -> bool:
        if path.suffix.lower() in SUSPICIOUS_EXTENSIONS:
            return True
        if path.is_file():
            entropy = self._estimate_entropy(path)
            if entropy is not None and entropy >= self.config.entropy_threshold:
                return True
        return False

    def _estimate_entropy(self, path: Path) -> Optional[float]:
        try:
            with path.open("rb") as handle:
                data = handle.read(self.config.entropy_sample_bytes)
        except (OSError, PermissionError):
            return None
        if not data:
            return None
        return _shannon_entropy(data)

    def _trigger_alert(self, reason: str) -> None:
        print(f"\nALERT: {reason}")
        if self.config.deny_write_on_alert:
            self._lockdown_folder()
        self._terminate_suspicious_processes()

    def _lockdown_folder(self) -> None:
        folder = str(self.config.folder)
        print(f"Applying lockdown to {folder}")
        try:
            os.system(f'icacls "{folder}" /deny Everyone:(W) >NUL 2>&1')
        except OSError as exc:
            print(f"Failed to apply ACL lockdown: {exc}")

    def _terminate_suspicious_processes(self) -> None:
        if psutil is None:
            print("psutil not installed; unable to terminate suspicious processes.")
            return
        offenders = self._find_processes_touching_folder()
        for proc in offenders:
            if proc.name().lower() in self.config.whitelist_processes:
                continue
            print(f"Terminating process {proc.pid} ({proc.name()})")
            try:
                proc.terminate()
            except psutil.Error as exc:
                print(f"Failed to terminate {proc.pid}: {exc}")

    def _find_processes_touching_folder(self) -> List["psutil.Process"]:
        offenders = []
        folder = str(self.config.folder).lower()
        for proc in psutil.process_iter(["name", "open_files"]):
            try:
                open_files = proc.info.get("open_files") or []
            except psutil.Error:
                continue
            for ofile in open_files:
                if ofile.path.lower().startswith(folder):
                    offenders.append(proc)
                    break
        return offenders

    def _snapshot_files(self) -> Dict[Path, float]:
        snapshot = {}
        for path in self._iter_files(self.config.folder):
            try:
                snapshot[path] = path.stat().st_mtime
            except OSError:
                continue
        return snapshot

    def _diff_snapshots(
        self, old: Dict[Path, float], new: Dict[Path, float]
    ) -> List[Tuple[Path, str]]:
        changes: List[Tuple[Path, str]] = []
        old_paths = set(old)
        new_paths = set(new)
        for added in new_paths - old_paths:
            changes.append((added, "created"))
        for removed in old_paths - new_paths:
            changes.append((removed, "deleted"))
        for common in old_paths & new_paths:
            if old[common] != new[common]:
                changes.append((common, "modified"))
        return changes

    def _iter_files(self, folder: Path) -> Iterable[Path]:
        for root, _, files in os.walk(folder):
            for name in files:
                yield Path(root) / name


def _shannon_entropy(data: bytes) -> float:
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    entropy = 0.0
    for count in counts:
        if count == 0:
            continue
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy


class WatchdogHandler(FileSystemEventHandler):
    def __init__(self, event_queue: "queue.Queue[FileEvent]") -> None:
        self.event_queue = event_queue

    def on_created(self, event) -> None:
        if not event.is_directory:
            self.event_queue.put(FileEvent(Path(event.src_path), "created", time.time()))

    def on_modified(self, event) -> None:
        if not event.is_directory:
            self.event_queue.put(FileEvent(Path(event.src_path), "modified", time.time()))

    def on_moved(self, event) -> None:
        if not event.is_directory:
            self.event_queue.put(FileEvent(Path(event.dest_path), "moved", time.time()))

    def on_deleted(self, event) -> None:
        if not event.is_directory:
            self.event_queue.put(FileEvent(Path(event.src_path), "deleted", time.time()))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Monitor a Windows folder for ransomware-like behavior and respond immediately."
    )
    parser.add_argument("folder", type=Path, help="Folder to monitor")
    parser.add_argument("--burst-threshold", type=int, default=25)
    parser.add_argument("--burst-window", type=int, default=10)
    parser.add_argument("--entropy-threshold", type=float, default=7.2)
    parser.add_argument("--no-lockdown", action="store_true")
    parser.add_argument(
        "--whitelist",
        nargs="*",
        default=["explorer.exe"],
        help="Process names to never terminate",
    )
    args = parser.parse_args()

    config = DefenderConfig(
        folder=args.folder,
        burst_threshold=args.burst_threshold,
        burst_window_seconds=args.burst_window,
        entropy_threshold=args.entropy_threshold,
        whitelist_processes={name.lower() for name in args.whitelist},
        deny_write_on_alert=not args.no_lockdown,
    )

    defender = RansomwareDefender(config)
    defender.start()


if __name__ == "__main__":
    main()
