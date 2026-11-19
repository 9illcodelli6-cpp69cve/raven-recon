import asyncio
import contextlib
import errno
import json
import os
import shutil
import signal
import subprocess
from dataclasses import asdict
from pathlib import Path

from .analysis import clean, js_endpoints
from .network import Requester
from .runtime.process_executor import hidden_process_kwargs
from .scope import canonical_url, hostname, origin

if os.name == "nt":
    import msvcrt
else:
    import fcntl


@contextlib.contextmanager
def workspace_lock(workspace):
    with (workspace / ".run.lock").open("a+b") as handle:
        try:
            if os.name == "nt":
                if handle.tell() == 0:
                    handle.write(b"\0")
                    handle.flush()
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                raise
            raise ValueError("Another operation is already writing this workspace") from None
        try:
            yield
        finally:
            if os.name == "nt":
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle, fcntl.LOCK_UN)


class Engine:
    def __init__(self, config, store, emit=None):
        self.config, self.store = config, store
        self.scope = config.scope
        self.emit = emit or (lambda event: None)
        self.stop = asyncio.Event()
        self.rejected = 0
        self.accepted = 0
        self.warnings = []
        self.run_id = None
        self.network = None

    def log(self, text):
        self.emit({"kind": "log", "text": clean(text, 1000)})

    def warn(self, text):
        self.warnings.append(text)
        self.log("NOTE  " + text)

    def start(self, mode):
        # A running row without the OS lock belongs to an interrupted process.
        self.store.db.execute("UPDATE runs SET state='interrupted' WHERE state='running'")
        self.run_id = self.store.start(mode, asdict(self.config))
        self.log(f"Run #{self.run_id} · {mode}")

    def ingest(self, value, source, evidence=None):
        value = value.strip()
        if not value or value.startswith("#"):
            return False
        try:
            if value.startswith("{"):
                record = json.loads(value)
                if not isinstance(record, dict):
                    raise ValueError("Expected object")
                value = record.get("url") or record.get("host") or record.get("input") or ""
                if not isinstance(value, str):
                    raise ValueError("Expected string")
            if "://" in value:
                value = canonical_url(value)
                if not self.scope.allows_url(value):
                    raise ValueError("Out of scope URL")
                fresh = self.store.url(value, source, self.run_id, evidence)
            else:
                value = hostname(value)
                if not self.scope.allows_host(value):
                    raise ValueError("Out of scope host")
                fresh = self.store.host(value, source, self.run_id)
            self.accepted += 1
            return fresh
        except (ValueError, TypeError, UnicodeError):
            self.rejected += 1
            return False

    async def _terminate(self, proc):
        if proc.returncode is None:
            if os.name == "nt":
                # The PID belongs to this run; /T includes descendants, and /F works
                # for console-free collectors without a CTRL_BREAK console binding.
                try:
                    killer = await asyncio.create_subprocess_exec(
                        "taskkill", "/PID", str(proc.pid), "/T", "/F",
                        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                    )
                    try:
                        await asyncio.wait_for(killer.wait(), 2)
                    except TimeoutError:
                        with contextlib.suppress(ProcessLookupError):
                            killer.kill()
                        await killer.wait()
                except OSError:
                    pass
                if proc.returncode is None:
                    with contextlib.suppress(ProcessLookupError):
                        proc.kill()
                await proc.wait()
                return
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGTERM)
            try:
                await asyncio.wait_for(proc.wait(), 2)
            except TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(proc.pid, signal.SIGKILL)
                await proc.wait()

    async def collect(self, tool, root):
        binary = shutil.which(tool)
        if not binary:
            self.warn(f"{tool} is missing; install it or import saved output")
            return
        if tool == "subfinder":
            args = [binary, "-d", root, "-silent", "-rl", str(max(1, int(self.config.rate)))]
        else:
            args = [binary, "--threads", "1", "--timeout", "10", "--retries", "0",
                    "--providers", "wayback,commoncrawl"]
            if self.scope.allows_host("scope-check." + root):
                args.append("--subs")
            args.append(root)
        self.log(f"Collecting {root} via {tool}")
        # Shared hidden-window flags (CANONICAL §2 C-4): one source of truth for the
        # CREATE_NO_WINDOW + CREATE_NEW_PROCESS_GROUP combination used here. group=True
        # preserves the CTRL_BREAK-capable process group this collector relied on; on
        # POSIX it yields {"start_new_session": True}, identical to the prior behavior.
        process_options = hidden_process_kwargs(group=True)
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            limit=65536, **process_options,
        )
        stderr_tail = bytearray()

        async def drain_stderr():
            while chunk := await proc.stderr.read(4096):
                stderr_tail.extend(chunk)
                del stderr_tail[:-1000]

        async def consume():
            count = 0
            while line := await proc.stdout.readline():
                if self.stop.is_set():
                    return
                count += 1
                self.ingest(line.decode("utf-8", errors="replace"), tool)
                if count % 200 == 0:
                    self.store.commit()
                    self.emit({"kind": "refresh"})
                if count >= self.config.max_records:
                    self.warn(f"{tool} output capped at {count} records")
                    return
            code = await proc.wait()
            if code:
                self.warn(f"{tool} exited {code}: {clean(stderr_tail.decode(errors='replace'), 240)}")

        stderr_task = asyncio.create_task(drain_stderr())
        read_task = asyncio.create_task(consume())
        stop_task = asyncio.create_task(self.stop.wait())
        try:
            done, _ = await asyncio.wait(
                [read_task, stop_task], timeout=self.config.tool_timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done:
                self.warn(f"{tool} timed out; partial results retained")
            elif read_task in done:
                await read_task
        except (ValueError, OSError) as exc:
            self.warn(f"{tool}: {clean(exc)}")
        finally:
            await self._terminate(proc)
            for task in (read_task, stderr_task, stop_task):
                task.cancel()
            await asyncio.gather(read_task, stderr_task, stop_task, return_exceptions=True)
            self.store.commit()
            self.emit({"kind": "refresh"})

    def import_file(self, path: Path, base=None):
        if not path.is_file() or path.stat().st_size > 20 * 1024 * 1024:
            raise ValueError("Import must be a regular file of at most 20 MiB")
        if base and not self.scope.allows_url(base):
            raise ValueError("JS base must be an in-scope HTTP(S) URL")
        with workspace_lock(self.store.workspace):
            self.start("javascript import" if base else "file import")
            try:
                if base:
                    self.analyze_js(path.read_text(encoding="utf-8", errors="replace"), base, "js:" + path.name)
                else:
                    with path.open(encoding="utf-8", errors="replace") as inp:
                        for number, line in enumerate(inp, 1):
                            if number > self.config.max_records:
                                self.warn("Import record limit reached")
                                break
                            self.ingest(line, "file:" + path.name)
                self.store.finish(self.run_id, "partial" if self.warnings else "complete")
            except Exception:
                self.store.finish(self.run_id, "failed")
                raise
        self.log(f"Imported {self.accepted} accepted records; {self.rejected} rejected")
        return self.run_id

    def analyze_js(self, text, base, source):
        count = 0
        for endpoint in js_endpoints(text, base):
            self.ingest(endpoint["url"], source, {**endpoint, "base": base})
            count += 1
            if count >= self.config.max_records:
                self.warn("JavaScript candidate limit reached")
                break

    async def probe_hosts(self, javascript=False):
        if not set(self.config.ports) & {80, 443}:
            self.warn("HTTP root probing needs port 80 or 443 enabled in scope.json")
            return
        hosts = [a["host"] for a in self.store.assets() if self.scope.allows_host(a["host"])]
        if len(hosts) > self.config.max_hosts:
            self.warn(f"Host budget: probing {self.config.max_hosts} of {len(hosts)} stored hosts")
        hosts = hosts[:self.config.max_hosts]
        scripts = {}
        completed = 0
        queue = asyncio.Queue()
        for host in hosts:
            queue.put_nowait(host)
        async with Requester(self.config, self.stop) as network:
            self.network = network

            async def worker():
                nonlocal completed
                while not queue.empty() and not self.stop.is_set() and network.sent < self.config.max_requests:
                    host = queue.get_nowait()
                    data = None
                    # Probe standard web roots only; never replay archived action URLs.
                    for scheme, port in (("https", 443), ("http", 80)):
                        if port not in self.config.ports:
                            continue
                        attempt, _ = await network.get(origin(host, scheme))
                        if attempt.get("blocked"):
                            break
                        data = attempt
                        if data["status"] is not None or self.stop.is_set():
                            break
                    if data is None:
                        queue.task_done()
                        continue
                    self.store.host(host, "http", self.run_id)
                    self.store.probe(host, data, self.run_id)
                    for script in data.get("scripts", []):
                        if self.scope.allows_url(script):
                            # Browser-relative fetch() calls resolve against the document URL.
                            scripts.setdefault(script, data.get("final_url", origin(host)))
                            self.ingest(script, "html:script")
                    completed += 1
                    self.log(f"{data.get('status') or 'ERR'}  {host}  {data.get('title') or data.get('error', '')}")
                    self.emit({"kind": "progress", "done": completed, "total": len(hosts), "requests": network.sent})
                    queue.task_done()

            await asyncio.gather(*(worker() for _ in range(self.config.concurrency)))
            if javascript:
                if len(scripts) > self.config.max_js:
                    self.warn(f"JavaScript budget: reading {self.config.max_js} of {len(scripts)} script URLs")
                for script, document in list(scripts.items())[:self.config.max_js]:
                    if self.stop.is_set():
                        break
                    data, body = await network.get(script)
                    if data.get("status") == 200 and not data.get("error") and "html" not in data.get("content_type", "").lower():
                        self.analyze_js(body.decode("utf-8", errors="replace"), document, "js:" + script)
                        self.log("JS analyzed  " + script)
                    else:
                        self.warn("JS skipped  " + script)
            if network.sent >= self.config.max_requests:
                self.warn("HTTP request budget reached")
            if network.blocked_hosts:
                self.warn("Hosts paused after HTTP 429: " + ", ".join(sorted(network.blocked_hosts)))

    async def run(self, passive=True, probe=False, javascript=False):
        if javascript and not probe:
            raise ValueError("JavaScript collection requires HTTP probing")
        with workspace_lock(self.store.workspace):
            self.start(" + ".join(filter(None, ["passive" if passive else "", "http" if probe else "", "js" if javascript else ""])))
            try:
                for root in self.config.roots:
                    self.ingest(root, "seed")
                    if passive:
                        for tool in ("subfinder", "gau"):
                            if self.stop.is_set():
                                break
                            await self.collect(tool, root)
                    if self.stop.is_set():
                        break
                if probe and not self.stop.is_set():
                    await self.probe_hosts(javascript)
                state = "stopped" if self.stop.is_set() else ("partial" if self.warnings else "complete")
                self.store.finish(self.run_id, state, "; ".join(self.warnings))
                self.log(f"Run #{self.run_id} {state} · {self.accepted} accepted / {self.rejected} rejected")
            except BaseException:
                self.store.finish(self.run_id, "interrupted")
                raise
            self.emit({"kind": "refresh"})
            return self.run_id
