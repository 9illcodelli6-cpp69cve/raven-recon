import asyncio
import sys

import pytest

from raven.config import Config
from raven.engine import Engine, workspace_lock
from raven.store import Store


def fake_tool(path, content):
    path.write_text("#!" + sys.executable + "\n" + content)
    path.chmod(0o700)
    return str(path)


@pytest.fixture(autouse=True)
def launch_python_fixture_scripts(monkeypatch):
    # Windows cannot execute the POSIX shebang scripts used as fake collectors.
    # Retain real subprocesses and arguments, only supplying their interpreter.
    original = asyncio.create_subprocess_exec

    async def launch(program, *args, **kwargs):
        from pathlib import Path
        candidate = Path(program)
        if candidate.is_file() and candidate.name in ("subfinder", "gau", "slow-tool", "tree-tool"):
            return await original(sys.executable, program, *args, **kwargs)
        return await original(program, *args, **kwargs)

    monkeypatch.setattr("raven.engine.asyncio.create_subprocess_exec", launch)


def test_workspace_lock_excludes_concurrent_writer_and_releases(tmp_path):
    with workspace_lock(tmp_path):
        with pytest.raises(ValueError, match="already writing"):
            with workspace_lock(tmp_path):
                pytest.fail("A second writer acquired the workspace lock")
    with workspace_lock(tmp_path):
        pass


async def test_external_collectors_provenance_and_partial_failure(tmp_path, monkeypatch):
    sub = fake_tool(tmp_path / "subfinder", "print('api.example.com')\nprint('out-of-scope.test')\n")
    gau = fake_tool(tmp_path / "gau", "print('https://api.example.com/v1/users?id=1')\nraise SystemExit(7)\n")
    monkeypatch.setattr("raven.engine.shutil.which", lambda name: {"subfinder": sub, "gau": gau}[name])
    config = Config("Test", ["example.com"], ["example.com", "*.example.com"])
    config.save(tmp_path)
    store = Store(tmp_path)
    engine = Engine(config, store)
    await engine.run()
    assert store.runs()[0]["state"] == "partial"
    assert engine.rejected == 1
    assert len(store.assets()) == 2
    assert store.urls()[0]["sources"] == ["gau"]
    assert "exited 7" in store.runs()[0]["note"]
    store.close()


async def test_stop_terminates_owned_collector_and_preserves_partial_data(tmp_path, monkeypatch):
    tool = fake_tool(tmp_path / "slow-tool", "import time\nprint('api.example.com', flush=True)\ntime.sleep(30)\n")
    monkeypatch.setattr("raven.engine.shutil.which", lambda name: tool)
    config = Config("Test", ["example.com"], ["example.com", "*.example.com"])
    config.save(tmp_path)
    store = Store(tmp_path)
    engine = Engine(config, store)
    task = asyncio.create_task(engine.run())
    for _ in range(100):
        if len(store.assets()) == 2:
            break
        await asyncio.sleep(0.02)
    engine.stop.set()
    await asyncio.wait_for(task, 4)
    assert store.runs()[0]["state"] == "stopped"
    assert len(store.assets()) == 2
    store.close()

