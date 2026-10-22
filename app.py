import copy
import json
import os
import re
import secrets
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.responses import FileResponse
from fastapi.exceptions import RequestValidationError
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator
from starlette.middleware.trustedhost import TrustedHostMiddleware

import engine
import reporting

ROOT = Path(__file__).parent
DATA = Path(os.environ.get("PATCH_DESK_DATA_DIR", str(ROOT / "data")))
TOKEN = secrets.token_urlsafe(32)
LOCK = threading.RLock()
SERVERS, CREDS, PLANS, JOBS, PROBES = {}, {}, {}, {}, {}
ACTIVE = set()

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "testserver"])


def save():
    DATA.mkdir(parents=True, exist_ok=True)
    # No credentials, probe keys, command output, or authentication token on disk.
    metadata = [{k: v for k, v in s.items() if k in {"id", "name", "host", "port", "ports", "connected_port", "username", "username2", "trusted", "health_url"}} for s in SERVERS.values()]
    temporary = DATA / "servers.tmp"
    temporary.write_text(json.dumps(metadata, ensure_ascii=False), encoding="utf-8")
    temporary.replace(DATA / "servers.json")


if (DATA / "servers.json").exists():
    for s in json.loads((DATA / "servers.json").read_text(encoding="utf-8")):
        s.setdefault("username2", "rooot")
        SERVERS[s["id"]] = s

# A credential-free snapshot is used only for this controlled local app upgrade.
# Preserve the user's inspection results without persisting their passwords.
if os.environ.get("PATCH_DESK_RESTORE"):
    restored = json.loads(Path(os.environ["PATCH_DESK_RESTORE"]).read_text(encoding="utf-8"))
    for old in restored.get("servers", []):
        if old.get("id") in SERVERS:
            for field in ("inventory", "assessment"):
                if field in old:
                    SERVERS[old["id"]][field] = old[field]
            if "assessment" in SERVERS[old["id"]]:
                SERVERS[old["id"]]["assessment"]["summary"] = engine.assessment_summary(old["assessment"])
    for job in restored.get("jobs", []):
        if job.get("status") == "finished":
            JOBS[job["id"]] = job


@app.middleware("http")
async def guard(request: Request, call_next):
    if request.url.path.startswith("/api/"):
        token = request.headers.get("x-patch-token", "")
        origin = request.headers.get("origin")
        if not secrets.compare_digest(token, TOKEN) or (origin and origin != str(request.base_url).rstrip("/")):
            return JSONResponse({"detail": "دسترسی معتبر نیست؛ صفحه محلی را دوباره باز کنید."}, 403)
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    return response


@app.exception_handler(Exception)
async def unexpected(request, exc):
    return JSONResponse({"detail": "عملیات ناموفق بود؛ اتصال، مجوز و وضعیت سرور را بررسی کنید."}, 500)


@app.exception_handler(RequestValidationError)
async def validation_error(request, exc):
    # Pydantic's default error input can contain submitted passwords.
    return JSONResponse({"detail": "اطلاعات فرم معتبر نیست؛ آدرس، پورت، URL و حداکثر سه رمز تک‌خطی را بررسی کنید."}, 422)


@app.get("/")
def index():
    return HTMLResponse((ROOT / "static/index.html").read_text(encoding="utf-8").replace("__TOKEN__", TOKEN))


@app.get("/help")
def help_page():
    return FileResponse(ROOT / "static/help.html", media_type="text/html")


@app.get("/guides/manual-patching.md")
def manual_guide():
    return FileResponse(ROOT / "docs/manual-patching.fa.md", media_type="text/plain; charset=utf-8")


class ServerInput(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=22, ge=1, le=65535)
    ports: list[int] = Field(default_factory=list, max_length=4)
    username: str = Field(min_length=1, max_length=80)
    username2: str = Field(default="rooot", max_length=80)
    passwords: list[SecretStr] = Field(min_length=1, max_length=3)
    sudo_password: SecretStr = SecretStr("")
    health_url: str = Field(default="", max_length=1000)

    @model_validator(mode="after")
    def ports_valid(self):
        if any(p < 1 or p > 65535 for p in self.ports):
            raise ValueError("پورت باید بین ۱ تا ۶۵۵۳۵ باشد")
        self.ports = list(dict.fromkeys(self.ports or [self.port]))
        self.port = self.ports[0]
        return self

    @field_validator("host")
    @classmethod
    def host_valid(cls, v):
        if not re.fullmatch(r"[a-zA-Z0-9_.:-]+", v) or v.startswith("-"):
            raise ValueError("نشانی میزبان معتبر نیست")
        return v.lower()

    @field_validator("passwords")
    @classmethod
    def passwords_valid(cls, v):
        if any(not p.get_secret_value() or any(c in p.get_secret_value() for c in "\n\r\x00") for p in v):
            raise ValueError("رمز خالی یا چندخطی مجاز نیست")
        return v

    @field_validator("sudo_password")
    @classmethod
    def sudo_valid(cls, v):
        if any(c in v.get_secret_value() for c in "\n\r\x00"):
            raise ValueError("رمز sudo چندخطی مجاز نیست")
        return v

    @field_validator("health_url")
    @classmethod
    def url_valid(cls, v):
        if v:
            parsed = urlparse(v)
            if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
                raise ValueError("نشانی سلامت باید HTTP/HTTPS و بدون رمز باشد")
        return v


def get_server(sid):
    if sid not in SERVERS:
        raise HTTPException(404, "سرور پیدا نشد")
    return SERVERS[sid]


def credential(server):
    if server["id"] not in CREDS:
        raise HTTPException(409, "رمزها فقط در حافظه‌اند؛ دوباره وارد کنید")
    return CREDS[server["id"]]


def reserve(sid):
    with LOCK:
        if sid in ACTIVE:
            raise HTTPException(409, "این سرور در حال پردازش است")
        ACTIVE.add(sid)


@app.get("/api/state")
def state():
    with LOCK:
        return reporting.review_state({"servers": [{**copy.deepcopy(s), "has_credentials": s["id"] in CREDS, "busy": s["id"] in ACTIVE} for s in SERVERS.values()], "jobs": copy.deepcopy(list(JOBS.values())), "plans": copy.deepcopy(PLANS)})


@app.post("/api/servers")
def add_server(body: ServerInput):
    with LOCK:
        if any(s["host"] == body.host and set(s.get("ports") or [s["port"]]) & set(body.ports) for s in SERVERS.values()):
            raise HTTPException(409, "برای این میزبان و پورت قبلاً سرور ثبت شده")
        sid = uuid.uuid4().hex
        SERVERS[sid] = {"id": sid, **body.model_dump(exclude={"passwords", "sudo_password"}), "trusted": None}
        CREDS[sid] = {"passwords": list(dict.fromkeys(p.get_secret_value() for p in body.passwords)), "sudo_password": body.sudo_password.get_secret_value()}
        save()
        return {"id": sid}


@app.put("/api/servers/{sid}/credentials")
def update_credentials(sid: str, body: ServerInput):
    with LOCK:
        server = get_server(sid)
        if sid in ACTIVE:
            raise HTTPException(409, "سرور در حال پردازش است")
        # Endpoint identity changes require removing/re-registering the server.
        if server["host"] != body.host:
            raise HTTPException(409, "برای تغییر آدرس، سرور را دوباره ثبت کنید")
        if any(s["id"] != sid and s["host"] == body.host and set(s.get("ports") or [s["port"]]) & set(body.ports) for s in SERVERS.values()):
            raise HTTPException(409, "این آدرس و پورت قبلاً ثبت شده است")
        for job in JOBS.values():
            if sid in job.get("servers", {}):
                job["servers"][sid].setdefault("endpoint", {"host": server["host"], "port": server["port"], "ports": server.get("ports") or [server["port"]]})
        server.update(body.model_dump(exclude={"passwords", "sudo_password"}))
        CREDS[sid] = {"passwords": list(dict.fromkeys(p.get_secret_value() for p in body.passwords)), "sudo_password": body.sudo_password.get_secret_value()}
        server.pop("inventory", None)
        server.pop("assessment", None)
        PLANS.pop(sid, None)
        save()
        return {"ok": True}


@app.delete("/api/servers/{sid}")
def delete_server(sid: str):
    return remove_servers([sid])


def remove_servers(ids):
    with LOCK:
        ids = list(dict.fromkeys(ids))
        for sid in ids:
            get_server(sid)
        if ACTIVE.intersection(ids):
            raise HTTPException(409, "یکی از سرورهای انتخاب‌شده در حال پردازش یا در صف است؛ ابتدا عملیات آن تمام یا متوقف شود. هیچ سروری حذف نشد.")
        removed = [(mapping, {sid: mapping[sid] for sid in ids if sid in mapping}) for mapping in (SERVERS, CREDS, PLANS, PROBES)]
        try:
            for mapping, values in removed:
                for sid in values:
                    mapping.pop(sid)
            save()
        except Exception:
            for mapping, values in removed:
                mapping.update(values)
            raise
    return {"ok": True, "deleted": len(ids)}


class DeleteInput(BaseModel):
    ids: list[str] = Field(min_length=1, max_length=1000)


@app.post("/api/servers/delete-selected")
def delete_selected(body: DeleteInput):
    return remove_servers(body.ids)


@app.post("/api/servers/{sid}/probe")
def probe_server(sid: str):
    s = get_server(sid)
    reserve(sid)
    try:
        observed = engine.probe(s["host"], s["port"])
        with LOCK:
            PROBES[sid] = {"key": observed, "time": time.time()}
            s["trusted"] = observed
            save()
        return observed
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(400, "دریافت هویت SSH ناموفق بود؛ آدرس و پورت را بررسی کنید") from None
    finally:
        with LOCK:
            ACTIVE.discard(sid)


class TrustInput(BaseModel):
    fingerprint: str


@app.post("/api/servers/{sid}/trust")
def trust_server(sid: str, body: TrustInput):
    with LOCK:
        s = get_server(sid)
        p = PROBES.get(sid)
        if not p or time.time() - p["time"] > 300 or body.fingerprint != p["key"]["fingerprint"]:
            raise HTTPException(409, "ابتدا هویت SSH را دوباره دریافت کنید")
        s["trusted"] = p["key"]
        save()
    return {"ok": True}


@app.post("/api/servers/{sid}/inspect")
def inspect_server(sid: str):
    s = get_server(sid)
    c = credential(s)
    reserve(sid)
    try:
        with engine.Remote(s, c) as remote:
            inventory = engine.inspect(remote)
            assessment = engine.assess(inventory, remote)
        with LOCK:
            s["inventory"], s["assessment"] = inventory, assessment
            PLANS.pop(sid, None)
            save()
        return {"inventory": inventory, "assessment": assessment}
    except Exception as exc:
        message = engine.redact(str(exc), c["passwords"] + [c["sudo_password"]])
        raise HTTPException(400, message[:3000]) from None
    finally:
        with LOCK:
            ACTIVE.discard(sid)


class Options(BaseModel):
    mode: str = "php"
    official_fallback: bool = False
    compose_dir: str = ""
    compose_service: str = ""


@app.post("/api/servers/{sid}/plan")
def plan_server(sid: str, body: Options):
    with LOCK:
        s = get_server(sid)
        if sid in ACTIVE or "inventory" not in s:
            raise HTTPException(409, "ابتدا شناسایی سرور را تکمیل کنید")
        try:
            plan = engine.make_plan(s, s["inventory"], body.model_dump())
        except ValueError as e:
            raise HTTPException(400, str(e)) from None
        plan["id"], plan["created"] = uuid.uuid4().hex, time.time()
        PLANS[sid] = plan
        return plan


class RunInput(BaseModel):
    plans: dict[str, str] = Field(min_length=1, max_length=100)
    parallel: int = Field(default=3, ge=1, le=6)
    backup_confirmed: bool = False
    stop_on_failure: bool = True


def health(remote, url):
    if url:
        result = remote.run("curl --fail --silent --show-error --max-time 30 --output /dev/null --url " + engine.q(url), timeout=40)
        if result.code:
            raise RuntimeError("تست HTTP سلامت برنامه ناموفق بود: " + result.output[-1000:])


def execute_one(job, sid, plan, server, creds):
    entry = job["servers"][sid]
    def log(name, output="", code=0):
        with LOCK:
            entry["events"].append({"time": time.time(), "name": name, "output": output[-12000:], "code": code})
    try:
        if job["cancel"]:
            entry["status"] = "skipped"
            return
        entry["status"], entry["phase"] = "running", "connection"
        session = engine.Remote(server, creds)
        session.on_progress = log
        with session as remote:
            with LOCK:
                for field in ("trusted", "authenticated_username", "connected_port"):
                    if field in server:
                        SERVERS[sid][field] = server[field]
                if creds.get("successful_username"):
                    CREDS[sid].update(creds)
                if server.get("connected_port"):
                    entry["connected_port"] = server["connected_port"]
            entry["phase"] = "شناسایی PHP و سیستم‌عامل"
            current = engine.inspect(remote)
            if plan is None:
                assessment = engine.assess(current, remote)
                with LOCK:
                    SERVERS[sid]["inventory"], SERVERS[sid]["assessment"] = current, assessment
                    entry["assessment"] = assessment
                    save()
                if assessment["summary"]["update_required"] is None:
                    entry["status"] = "php-not-detected"
                    log("PHP در مسیرهای بررسی‌شده شناسایی نشد؛ فرمان آپدیت اجرا نشد.")
                    return
                if assessment["summary"]["update_required"] is False:
                    entry["status"] = "up-to-date"
                    log("اوکی؛ آپدیت لازم نیست. هیچ بسته‌ای تغییر نکرد.")
                    return
                log("آپدیت لازم است؛ آماده‌سازی خودکار عملیات")
                parts, unresolved = [], []
                host_assessment = {**assessment, "containers": [], "discovery_errors": []}
                if current["packages"] and engine.assessment_summary(host_assessment)["update_required"]:
                    parts.append(engine.make_plan(server, current, {"mode": "php", "official_fallback": job.get("official_fallback", True)}))
                compose_seen = set()
                for container in current["containers"]:
                    if not container.get("php") or container.get("status") == "fixed-upstream":
                        continue
                    if not container.get("compose_dir") or not container.get("compose_service") or not container.get("compose_project"):
                        unresolved.append(container["name"])
                        continue
                    key = (container["compose_dir"], container["compose_service"], container["compose_project"])
                    if key in compose_seen:
                        continue
                    compose_seen.add(key)
                    parts.append(engine.make_plan(server, current, {"mode": "compose", "compose_dir": container["compose_dir"], "compose_service": container["compose_service"], "compose_files": container.get("compose_files", []), "compose_project": container["compose_project"]}))
                if unresolved:
                    entry["unresolved_containers"] = unresolved
                    log("این کانتینرها Compose قابل‌شناسایی ندارند و خودکار تغییر نمی‌کنند: " + ", ".join(unresolved))
                if not parts:
                    entry["status"] = "needs-configuration"
                    log("آپدیت لازم است، اما مسیر نصب یا پروژه قابل به‌روزرسانی خودکار پیدا نشد؛ تنظیمات این سرور بررسی شود.")
                    return
                plan = {"digest": engine.inventory_digest(current), "steps": [step for part in parts for step in part["steps"]],
                        "fallback": parts[0]["fallback"], "warnings": [w for part in parts for w in part["warnings"]], "options": {"mode": "automatic"}}
                entry["plan"] = plan
            if engine.inventory_digest(current) != plan["digest"]:
                raise RuntimeError("از زمان ساخت برنامه، بسته‌ها/سرویس‌ها/کانتینرها تغییر کرده‌اند؛ شناسایی و برنامه جدید لازم است.")
            health(remote, server.get("health_url"))
            entry["phase"] = "بررسی دسترسی مدیریتی"
            privilege = remote.run("true", True, timeout=30)
            if privilege.code:
                entry["diagnosis"] = engine.classify(privilege.output, entry["phase"])
                raise RuntimeError(privilege.output)
            log("بررسی مجدد وضعیت و سلامت اولیه انجام شد")
            fallback_done = False
            compose_version = None
            for step in plan["steps"]:
                if job["cancel"]:
                    entry["status"] = "stopped-between-steps"
                    log("توقف در مرز مراحل؛ عملیات انجام‌شده rollback نشده است")
                    return
                if fallback_done and step.get("package_phase"):
                    continue
                log("شروع: " + step["name"])
                entry["phase"] = step["name"]
                if "-y " in step["command"] or " up -d " in step["command"] or "systemctl restart" in step["command"]:
                    entry["changes_started"] = True
                result = remote.run(step["command"], True)
                log(step["name"], result.output, result.code)
                if result.code:
                    diagnosis = engine.classify(result.output, entry["phase"])
                    entry["diagnosis"] = diagnosis
                    if (step.get("repository") or step.get("package_phase")) and diagnosis["kind"] == "mirror" and plan["fallback"] and not fallback_done:
                        for alternate in plan["fallback"]:
                            log("شروع: " + alternate["name"])
                            r = remote.run(alternate["command"], True)
                            log(alternate["name"], r.output, r.code)
                            if r.code:
                                entry["diagnosis"] = engine.classify(r.output)
                                raise RuntimeError("مخزن رسمی جایگزین هم ناموفق بود")
                        fallback_done = True
                    else:
                        raise RuntimeError(diagnosis["advice"])
                if step.get("verify_compose"):
                    compose_version = result.output.strip()
            entry["phase"] = "تأیید نتیجه پس از آپدیت"
            after = engine.inspect(remote)
            assessment = engine.assess(after, remote)
            health(remote, server.get("health_url"))
            with LOCK:
                SERVERS[sid]["inventory"], SERVERS[sid]["assessment"] = after, assessment
                entry["assessment"] = assessment
                entry["status"] = "updated" if assessment["summary"]["update_required"] is False else "updated-needs-verification"
                if compose_version:
                    entry["compose_php"] = compose_version
                    entry["compose_cve"] = engine.upstream_status(compose_version)
                entry["http_checked"] = bool(server.get("health_url"))
                save()
            log("به‌روزرسانی پایان یافت؛ شواهد PHP و سلامت ثبت شد. تأیید نهایی تمام نصب‌ها جداگانه است.")
    except Exception as exc:
        entry["status"] = "failed"
        message = engine.redact(str(exc), creds["passwords"] + [creds.get("sudo_password", "")])
        if not entry.get("diagnosis") or entry["diagnosis"].get("kind") == "unknown":
            entry["diagnosis"] = engine.classify(message, entry.get("phase", "operation"))
        entry["failure"] = {"stage": entry.get("phase"), "message": message[:3000], "changes_started": bool(entry.get("changes_started"))}
        log("توقف عملیات", message[:3000], 1)
        if job["stop_on_failure"]:
            job["cancel"] = True
    finally:
        with LOCK:
            ACTIVE.discard(sid)


def run_batch(job, items):
    with ThreadPoolExecutor(max_workers=job["parallel"]) as pool:
        futures = [pool.submit(execute_one, job, *item) for item in items]
        for future in as_completed(futures):
            future.result()
    with LOCK:
        job["status"] = "finished"
        job["finished"] = time.time()
    # Credentials remain only in the session vault; no job snapshots store them.


@app.post("/api/jobs")
def start_job(body: RunInput):
    if not body.backup_confirmed:
        raise HTTPException(400, "وجود backup/snapshot قابل بازیابی را تأیید کنید")
    items = []
    with LOCK:
        for sid, pid in body.plans.items():
            s = get_server(sid)
            c = credential(s)
            p = PLANS.get(sid)
            if sid in ACTIVE or not p or p["id"] != pid or time.time() - p["created"] > 1800:
                raise HTTPException(409, "برنامه منقضی یا سرور مشغول است؛ برنامه جدید بسازید")
            items.append((sid, copy.deepcopy(p), copy.deepcopy(s), copy.deepcopy(c)))
        for sid in body.plans:
            ACTIVE.add(sid)
            PLANS.pop(sid, None)  # Plans are single use, including after failure.
        jid = uuid.uuid4().hex
        job = {"id": jid, "created": time.time(), "status": "running", "parallel": body.parallel,
               "cancel": False, "stop_on_failure": body.stop_on_failure,
               "servers": {sid: {"name": s["name"], "status": "queued", "events": [], "plan": p} for sid, p, s, c in items}}
        JOBS[jid] = job
        threading.Thread(target=run_batch, args=(job, items), daemon=True).start()
        return {"id": jid}


class BatchInput(BaseModel):
    servers: list[ServerInput] = Field(min_length=1, max_length=100)
    parallel: int = Field(default=1, ge=1, le=6)
    official_fallback: bool = True


@app.post("/api/batch")
def automatic_batch(body: BatchInput):
    with LOCK:
        endpoints = [(s.host, s.port) for s in body.servers]
        if len(set(endpoints)) != len(endpoints):
            raise HTTPException(400, "در لیست IP یا پورت تکراری وجود دارد؛ تکراری‌ها را حذف کنید")
        if any(a.host == b.host and set(a.ports) & set(b.ports) for i, a in enumerate(body.servers) for b in body.servers[i+1:]):
            raise HTTPException(400, "پورت‌های دو ردیف یک IP هم‌پوشانی دارند؛ آن‌ها را در یک ردیف وارد کنید")
        existing = {(s["host"], s["port"]): s for s in SERVERS.values()}
        def resolve(config):
            direct = existing.get((config.host, config.port))
            if direct:
                return direct
            matches = [s for s in SERVERS.values() if s["host"] == config.host and set(s.get("ports") or [s["port"]]) & set(config.ports)]
            if len(matches) > 1:
                raise HTTPException(409, "پورت‌های این IP به چند رکورد ثبت‌شده اشاره دارند؛ تنظیمات اتصال را جداگانه اصلاح کنید")
            return matches[0] if matches else None
        if any((resolve(config) or {}).get("id") in ACTIVE for config in body.servers):
            raise HTTPException(409, "یکی از این سرورها هم‌اکنون در حال پردازش است")
        ids, items = [], []
        for config in body.servers:
            server = resolve(config)
            if server is None:
                sid = add_server(config)["id"]
                server = SERVERS[sid]
            else:
                sid = server["id"]
                for old_job in JOBS.values():
                    if sid in old_job.get("servers", {}):
                        old_job["servers"][sid].setdefault("endpoint", {"host": server["host"], "port": server["port"], "ports": server.get("ports") or [server["port"]]})
                # Explicit new batch settings replace user candidates, never unrelated endpoint identity.
                server["username"], server["username2"] = config.username, config.username2
                server["port"], server["ports"] = config.port, config.ports
                previous_user = CREDS.get(sid, {}).get("successful_username")
                CREDS[sid] = {"passwords": list(dict.fromkeys(p.get_secret_value() for p in config.passwords)), "sudo_password": ""}
                if previous_user in (config.username, config.username2):
                    CREDS[sid]["successful_username"] = previous_user
            ids.append(sid)
            items.append((sid, None, copy.deepcopy(server), copy.deepcopy(CREDS[sid])))
        save()
        jid = uuid.uuid4().hex
        job = {"id": jid, "created": time.time(), "status": "running", "parallel": body.parallel,
               "cancel": False, "stop_on_failure": False, "official_fallback": body.official_fallback,
               "automatic": True, "servers": {sid: {"name": s["name"], "status": "queued", "events": [], "plan": None} for sid, p, s, c in items}}
        for sid in ids:
            ACTIVE.add(sid)
            PLANS.pop(sid, None)
        JOBS[jid] = job
        threading.Thread(target=run_batch, args=(job, items), daemon=True).start()
        return {"id": jid, "server_ids": ids}


@app.post("/api/jobs/{jid}/stop")
def stop_job(jid: str):
    with LOCK:
        if jid not in JOBS:
            raise HTTPException(404, "عملیات پیدا نشد")
        JOBS[jid]["cancel"] = True
    return {"ok": True, "notice": "توقف قبل از مرحله بعد اعمال می‌شود؛ مدیر بسته در حال اجرا قطع نمی‌شود."}


app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("PATCH_DESK_PORT", "8765")), access_log=False)
