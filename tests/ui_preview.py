"""Disposable UI acceptance server on 8766. All SSH/package operations are fake."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app
import engine
import uvicorn

for mapping in (app.SERVERS, app.CREDS, app.PLANS, app.JOBS, app.PROBES):
    mapping.clear()
app.ACTIVE.clear()
app.DATA = app.ROOT / "data" / "ui-fixture"
app.DATA.mkdir(parents=True, exist_ok=True)

updated = set()


class FakeRemote:
    def __init__(self, server, credentials): self.server = server
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def run(self, command, *args, **kwargs):
        if "-y upgrade" in command:
            updated.add(self.server["host"])
        return engine.Result(0, "نتیجه شبیه‌سازی‌شده؛ هیچ دستور واقعی اجرا نشده است.")


def inspect(remote):
    version = "8.4.27" if remote.server["host"].endswith(".2") or remote.server["host"] in updated else "8.4.12"
    return {"os": {"ID": "almalinux", "VERSION_ID": "9", "PRETTY_NAME": "AlmaLinux · نمونه آزمایشی"},
            "packages": [{"name": "php-cli", "version": version + "-1.el9.remi"}], "runtime": "PHP " + version + " (cli)",
            "services": ["php-fpm.service"], "containers": [], "disk": "fixture", "docker_error": None, "notice": "داده آزمایشی؛ اتصال واقعی وجود ندارد."}


engine.Remote = FakeRemote
engine.inspect = inspect
uvicorn.run(app.app, host="127.0.0.1", port=8766, access_log=False)
