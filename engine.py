"""SSH execution and conservative, reviewable patch plans. No remote shell from UI."""
import base64
import hashlib
import json
import re
import shlex
import socket
import time
from dataclasses import dataclass

import paramiko
from packaging.version import Version, InvalidVersion

q = shlex.quote
FIXED = {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"}
UBUNTU = {"22.04": ("php8.1", "8.1.2-1ubuntu2.28"), "24.04": ("php8.3", "8.3.6-0ubuntu0.24.04.13"), "26.04": ("php8.5", "8.5.4-0ubuntu1.5"), "26.10": ("php8.5", "8.5.9-0ubuntu2.1")}
DEBIAN = {"12": ("php8.2", "8.2.35-1~deb12u1"), "13": ("php8.4", "8.4.27-1~deb13u1")}


def fingerprint(key):
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def probe(host, port):
    with socket.create_connection((host, port), timeout=12) as sock:
        transport = paramiko.Transport(sock)
        try:
            transport.start_client(timeout=12)
            key = transport.get_remote_server_key()
            return {"type": key.get_name(), "key": key.get_base64(), "fingerprint": fingerprint(key)}
        finally:
            transport.close()


class PinnedKey(paramiko.MissingHostKeyPolicy):
    def __init__(self, expected):
        self.expected = expected

    def missing_host_key(self, client, hostname, key):
        if fingerprint(key) != self.expected:
            raise RuntimeError("هویت SSH سرور تغییر کرده؛ اتصال متوقف شد.")


class AutomaticKey(paramiko.MissingHostKeyPolicy):
    """The operator explicitly requested accepting every observed SSH host key."""
    def __init__(self, server):
        self.server = server

    def missing_host_key(self, client, hostname, key):
        self.server["trusted"] = {"type": key.get_name(), "key": key.get_base64(), "fingerprint": fingerprint(key)}


@dataclass
class Result:
    code: int
    output: str


def redact(value, secrets):
    for secret in sorted((s for s in secrets if s), key=len, reverse=True):
        value = value.replace(secret, "[REDACTED]")
    return value


class Remote:
    def __init__(self, server, credentials):
        self.server, self.credentials = server, credentials
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(AutomaticKey(server))

    def __enter__(self):
        candidates = self.credentials["passwords"]
        users = list(dict.fromkeys(u for u in [self.credentials.get("successful_username"), self.server["username"], self.server.get("username2")] if u))
        configured = self.server.get("ports") or [self.server["port"]]
        preferred = self.credentials.get("successful_port", self.server.get("connected_port"))
        ports = list(dict.fromkeys(([preferred] if preferred in configured else []) + configured))[:4]
        attempts = [(port, user, password) for port in ports for user in users for password in candidates]
        unavailable, authentication_failed = {}, False
        for index, (port, username, password) in enumerate(attempts):
            if port in unavailable:
                continue
            if callable(getattr(self, "on_progress", None)):
                self.on_progress(f"اتصال SSH به پورت {port} با کاربر {username}")
            try:
                self.client.connect(self.server["host"], port=port, username=username,
                                    password=password, allow_agent=False, look_for_keys=False,
                                    timeout=15, banner_timeout=15, auth_timeout=20)
                self.active_password = password
                self.active_username = username
                self.credentials["successful_username"] = username
                self.credentials["successful_port"] = port
                self.server["authenticated_username"] = username
                self.server["connected_port"] = port
                # Avoid repeating rejected candidates on every inspection / job.
                self.credentials["passwords"] = [password] + [p for p in candidates if p != password]
                return self
            except paramiko.AuthenticationException:
                self.client.close()
                authentication_failed = True
                time.sleep(2)
            except (OSError, EOFError, paramiko.SSHException) as exc:
                self.client.close()
                unavailable[port] = str(exc)[:300]
            except Exception:
                self.client.close()
                raise
        if authentication_failed:
            raise RuntimeError("SSH_AUTH_FAILED: سرویس SSH پاسخ داد، اما ورود با کاربران و رمزهای تعیین‌شده ناموفق بود. پورت‌های امتحان‌شده: " + ", ".join(map(str, ports)))
        raise RuntimeError("SSH_UNREACHABLE: اتصال SSH روی هیچ‌کدام از پورت‌های مشخص‌شده برقرار نشد. " + "; ".join(f"{port}: {reason}" for port, reason in unavailable.items()))

    def __exit__(self, *args):
        self.client.close()

    def run(self, script, privileged=False, timeout=900):
        # Password travels on stdin, never in the remote command or process arguments.
        command = "sh -c " + q(script)
        if privileged and not hasattr(self, "is_root"):
            identity = self.run("id -u", timeout=20)
            if identity.code or not identity.output.strip().isdigit():
                raise RuntimeError("تشخیص سطح دسترسی کاربر ناموفق بود")
            self.is_root = identity.output.strip() == "0"
        sudo = privileged and not self.is_root
        if sudo:
            command = "sudo -S -p '' -- " + command
        stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        if sudo:
            stdin.write(self.active_password)
            stdin.write("\n")
            stdin.flush()
        stdin.channel.shutdown_write()
        channel = stdout.channel
        started, output, size = time.monotonic(), [], 0
        while True:
            for ready, receive in ((channel.recv_ready, channel.recv), (channel.recv_stderr_ready, channel.recv_stderr)):
                if ready():
                    chunk = receive(32768)
                    size += len(chunk)
                    if size < 2_000_000:
                        output.append(chunk.decode("utf-8", "replace"))
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                break
            if time.monotonic() - started > timeout:
                channel.close()
                raise RuntimeError("مهلت SSH تمام شد؛ وضعیت عملیات روی سرور نامشخص است. قبل از تکرار بررسی شود.")
            time.sleep(.05)
        return Result(channel.recv_exit_status(), redact("".join(output), self.credentials["passwords"] + [self.credentials.get("sudo_password", "")]))


def classify(output, phase="operation"):
    text = output.lower()
    if any(s in text for s in ("not in the sudoers", "not allowed to execute", "a password is required", "incorrect password attempt", "sudo: command not found", "sudo: sorry")):
        return {"kind": "sudo", "title": "کاربر مجوز sudo ندارد یا sudo قابل استفاده نیست", "advice": "با کاربر root یا حساب دارای مجوز sudo وصل شوید؛ مدیر سرور مجوز را بررسی کند. ابزار sudoers را خودکار تغییر نمی‌دهد.", "phase": phase}
    if "ssh_auth_failed" in text or "authentication failed" in text or "authenticationexception" in text:
        return {"kind": "ssh-auth", "title": "SSH پاسخ داد؛ نام کاربری یا رمز پذیرفته نشد", "advice": "کاربرهای root/rooot، رمزها و مجازبودن ورود با رمز را بررسی کنید. این خطا مربوط به mirror نیست.", "phase": "connection"}
    if "ssh_unreachable" in text or "unable to connect to port" in text or (phase == "connection" and any(s in text for s in ("timed out", "timeout", "no route", "connection refused"))):
        return {"kind": "ssh-unreachable", "title": "اتصال SSH برقرار نشد", "advice": "پورت‌های SSH، روشن‌بودن سرور، فایروال و مسیر/VPN را بررسی کنید. از این خطا به‌تنهایی نمی‌توان علت شبکه را قطعی دانست؛ هنوز بررسی PHP شروع نشده است.", "phase": "connection"}
    rules = [
        ("signature", ["no_pubkey", "not signed", "gpg check failed", "signature verification", "public key for"], "امضای مخزن/کلید معتبر نیست؛ کنترل امضا حفظ می‌شود. کلید رسمی و ساعت را بررسی کنید."),
        ("lock", ["could not get lock", "another app is currently", "waiting for process"], "مدیر بسته مشغول است؛ پس از پایان فرایند دوباره بررسی کنید. قفل حذف نمی‌شود."),
        ("disk", ["no space left", "not enough free space"], "فضای دیسک کافی نیست؛ پاک‌سازی نیاز به بررسی جداگانه دارد."),
        ("dns", ["temporary failure resolving", "could not resolve", "couldn't resolve"], "DNS پاسخ نمی‌دهد؛ resolver و مسیر شبکه را بررسی کنید."),
        ("tls", ["certificate verification", "certificate verify", "ssl certificate"], "گواهی TLS یا ساعت سرور مشکل دارد؛ TLS غیرفعال نمی‌شود."),
        ("mirror", ["patch_missing", "404", "failed to fetch", "cannot download", "all mirrors were tried", "connection timed out", "connection refused", "could not connect", "failed to download metadata"], "مخزن در دسترس نیست یا بسته اصلاح‌شده را ندارد؛ fallback رسمیِ از پیش مشخص‌شده قابل امتحان است."),
        ("dependency", ["unmet dependencies", "conflicting requests", "broken packages", "nothing provides"], "تعارض وابستگی؛ حذف یا تغییر شاخه خودکار انجام نمی‌شود."),
    ]
    for kind, needles, advice in rules:
        if any(s in text for s in needles):
            titles = {"signature": "امضای مخزن معتبر نیست", "lock": "مدیر بسته مشغول است", "disk": "فضای دیسک کافی نیست", "dns": "نام مخزن resolve نشد", "tls": "خطای گواهی یا ساعت سیستم", "mirror": "مخزن یا بسته در دسترس نیست", "dependency": "تعارض وابستگی بسته‌ها"}
            return {"kind": kind, "title": titles[kind], "advice": advice, "phase": phase}
    if "مهلت ssh" in text or "timed out" in text:
        return {"kind": "command-timeout", "title": "مهلت اجرای فرمان تمام شد", "advice": "فرمان ممکن است روی سرور ادامه یافته باشد؛ پیش از تکرار، وضعیت عملیات و مدیر بسته بررسی شود.", "phase": phase}
    return {"kind": "unknown", "title": "عملیات در این مرحله متوقف شد", "advice": "جزئیات فنی همین خطا را باز کنید؛ علت هنوز قطعی نیست و دستور حدسی اجرا نمی‌شود.", "phase": phase}


def is_php_meta(package):
    return package.get("name", "").split(":")[0] in {"php", "php-common"} and not re.match(r"^(?:\d+:)?\d+\.\d+\.\d+", package.get("version", ""))


def upstream_status(version):
    try:
        v = Version(version)
        branch = f"{v.major}.{v.minor}"
        if branch not in FIXED:
            return "unknown"
        return "fixed-upstream" if v >= Version(FIXED[branch]) else "needs-vendor-evidence"
    except InvalidVersion:
        return "unknown"


def inspect(remote):
    def read(command, privileged=False):
        r = remote.run(command, privileged, timeout=60)
        if r.code:
            raise RuntimeError(r.output[-2000:] or "بررسی سرور ناموفق بود")
        return r.output.strip()
    osinfo = {}
    for line in read("cat /etc/os-release").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            osinfo[k] = v.strip('"')
    packages = read("if command -v dpkg-query >/dev/null; then dpkg-query -W -f='${binary:Package}\\t${Version}\\t${db:Status-Status}\\n' '*php*' 2>/dev/null | awk '$3 == \"installed\" {print $1 \"\\t\" $2}'; elif command -v rpm >/dev/null; then rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n' | grep -E '^php' || :; fi")
    parsed = []
    for line in packages.splitlines():
        parts = line.split("\t")
        if len(parts) == 2 and re.fullmatch(r"[a-zA-Z0-9.+:_-]+", parts[0]):
            parsed.append({"name": parts[0], "version": parts[1]})
    runtime = read("for p in /usr/bin/php /usr/bin/php[0-9]* /usr/local/bin/php /usr/sbin/php-fpm*; do [ -x \"$p\" ] || continue; case \"$p\" in *config*|*ize*) continue;; esac; printf '%s ' \"$p\"; \"$p\" -v 2>/dev/null | head -n 1; done; true")
    services = read("if command -v systemctl >/dev/null; then systemctl list-units --type=service --state=running --no-legend --plain | awk '{print $1}' | grep -E '^(php.*fpm|apache2|httpd)\\.service$' || :; fi")
    disk = read("df -Pm / /var /tmp | tail -n +2")
    # Deliberately inspect narrow Docker fields, never environment variables / full config.
    docker_present = read("if command -v docker >/dev/null; then echo installed; fi") == "installed"
    docker = remote.run("docker ps --format '{{.ID}}|{{.Names}}|{{.Image}}'", True, timeout=60) if docker_present else Result(0, "")
    containers = []
    if not docker.code:
        for line in docker.output.strip().splitlines():
            parts = line.split("|", 2)
            if len(parts) == 3 and re.fullmatch(r"[a-f0-9]{12,64}", parts[0]):
                r = remote.run("docker exec " + q(parts[0]) + " php -r 'echo PHP_VERSION;'", True, timeout=30)
                labels = remote.run("docker inspect --format " + q('{{ index .Config.Labels "com.docker.compose.project.working_dir" }}|{{ index .Config.Labels "com.docker.compose.service" }}|{{ index .Config.Labels "com.docker.compose.project.config_files" }}|{{ index .Config.Labels "com.docker.compose.project" }}') + " " + q(parts[0]), True, timeout=30)
                compose = labels.output.strip().split("|") if labels.code == 0 else []
                containers.append({"id": parts[0], "name": parts[1], "image": parts[2], "php": r.output.strip() if not r.code else None,
                                   "status": upstream_status(r.output.strip()) if not r.code else "not-detected",
                                   "compose_dir": compose[0] if len(compose) == 4 and compose[0].startswith("/") else "",
                                   "compose_service": compose[1] if len(compose) == 4 else "",
                                   "compose_files": [f for f in compose[2].split(",") if f.startswith("/")] if len(compose) == 4 else [],
                                   "compose_project": compose[3] if len(compose) == 4 else ""})
    return {"os": osinfo, "packages": parsed, "runtime": runtime, "services": services.splitlines(), "disk": disk,
            "containers": containers, "docker_error": classify(docker.output) if docker.code else None,
            "notice": "کشف Docker فقط کانتینرهای در حال اجرا و php در PATH را پوشش می‌دهد؛ کانتینر متوقف، Kubernetes، نصب سفارشی و کنترل‌پنل نیاز به بررسی جداگانه دارند."}


def inventory_digest(inventory):
    # Free-space and incidental output do not invalidate a reviewed package plan.
    material = {k: inventory[k] for k in ("os", "packages", "services", "containers")}
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()


def make_plan(server, inventory, options):
    distro = inventory["os"].get("ID")
    packages = [p["name"] for p in inventory["packages"] if p["name"].startswith("php") or p["name"].startswith("libapache2-mod-php")]
    steps, fallback, warnings = [], [], []
    mode = options.get("mode", "php")
    if mode == "compose":
        directory, service = options.get("compose_dir", ""), options.get("compose_service", "")
        if not directory.startswith("/") or "\n" in directory or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]*", service):
            raise ValueError("مسیر مطلق Compose و نام سرویس معتبر لازم است.")
        files = options.get("compose_files", [])
        if not isinstance(files, list) or any(not isinstance(f, str) or not f.startswith("/") or "\n" in f for f in files):
            raise ValueError("مسیر فایل Compose معتبر نیست")
        project = options.get("compose_project", "")
        if project and not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", project):
            raise ValueError("نام پروژه Compose معتبر نیست")
        prefix = "cd " + q(directory) + " && docker compose " + ("-p " + q(project) + " " if project else "") + "".join("-f " + q(f) + " " for f in files)
        steps = [{"name": "دریافت image تنظیم‌شده در Compose", "command": prefix + "pull " + q(service)},
                 {"name": "جایگزینی سرویس و انتظار سلامت", "command": prefix + "up -d --no-deps --no-build --wait --wait-timeout 120 " + q(service)},
                 {"name": "بررسی PHP داخل سرویس", "command": prefix + "exec -T " + q(service) + " php -r 'echo PHP_VERSION;'", "verify_compose": True}]
        warnings.append("image همان فایل Compose دریافت می‌شود؛ tag قدیمی یا digest ثابت خودبه‌خود به نسخه امن تبدیل نمی‌شود. برنامه image اصلاح‌شده و نسخه داخل کانتینر را بررسی می‌کند. ساخت image سفارشی و rollback خودکار در این نسخه نیست.")
    elif distro in ("ubuntu", "debian", "almalinux"):
        if mode not in ("php", "system"):
            raise ValueError("حالت عملیات معتبر نیست")
        if not packages and mode == "php":
            raise ValueError("بسته PHP روی میزبان پیدا نشد؛ برای کانتینر از حالت Compose استفاده کنید.")
        target = " ".join(q(p) for p in packages)
        backup = "mkdir -p /var/backups/patch-desk && chmod 700 /var/backups/patch-desk && umask 077 && tar -czf /var/backups/patch-desk/config-$(date +%Y%m%d-%H%M%S).tgz " + ("/etc/apt" if distro in ("ubuntu", "debian") else "/etc/yum.repos.d")
        steps.append({"name": "بایگانی تنظیمات مخازن" , "command": backup})
        if distro in ("ubuntu", "debian"):
            apt = "DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=3 -o DPkg::Lock::Timeout=30 -o Dpkg::Options::=--force-confold "
            update = apt + "-o APT::Update::Error-Mode=any update"
            upgrade = apt + ("--no-remove -y upgrade" if mode == "system" else "--no-remove --only-upgrade -y install " + target)
            simulate = apt + ("--no-remove -s upgrade" if mode == "system" else "--no-remove --only-upgrade -s install " + target)
            steps.append({"name": "به‌روزرسانی فهرست بسته‌ها", "command": update, "repository": True})
            baseline = (UBUNTU if distro == "ubuntu" else DEBIAN).get(inventory["os"].get("VERSION_ID"))
            if baseline:
                branch, minimum = baseline
                for package in packages:
                    if package.split(":")[0] in {branch + "-cli", branch + "-common", branch + "-fpm", branch + "-cgi", "libapache2-mod-" + branch}:
                        check = "candidate=$(apt-cache policy " + q(package) + " | awk '/Candidate:/ {print $2}') && dpkg --compare-versions \"$candidate\" ge " + q(minimum) + " || { echo PATCH_MISSING; exit 42; }"
                        steps.append({"name": "بررسی وجود وصله در mirror برای " + package, "command": check, "repository": True, "package_phase": True})
            steps.extend([{"name": "شبیه‌سازی تغییر بسته‌ها", "command": simulate, "package_phase": True}, {"name": "نصب به‌روزرسانی‌ها", "command": upgrade, "package_phase": True}])
            codename = inventory["os"].get("VERSION_CODENAME", "")
            if distro == "ubuntu" and codename in {"jammy", "noble", "resolute", "stonking"}:
                setup = "PATCHDIR=$(mktemp -d /var/tmp/patch-desk.XXXXXX) && chmod 755 \"$PATCHDIR\" && mkdir -p \"$PATCHDIR/lists/partial\" && arch=$(dpkg --print-architecture) && case \"$arch\" in amd64|i386) base=https://archive.ubuntu.com/ubuntu; security=https://security.ubuntu.com/ubuntu;; *) base=https://ports.ubuntu.com/ubuntu-ports; security=$base;; esac && printf '%s\\n' \"deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] $base " + codename + " main restricted universe multiverse\" \"deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] $base " + codename + "-updates main restricted universe multiverse\" \"deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] $security " + codename + "-security main restricted universe multiverse\" > \"$PATCHDIR/sources.list\" && "
                isolated = apt + '-o Dir::Etc::sourcelist="$PATCHDIR/sources.list" -o Dir::Etc::sourceparts=- -o Dir::State::lists="$PATCHDIR/lists" '
                fallback = [{"name": "مخزن رسمی موقت Ubuntu با امضای معتبر", "command": setup + isolated + "-o APT::Update::Error-Mode=any update && " + isolated + ("--no-remove -s upgrade && " + isolated + "--no-remove -y upgrade" if mode == "system" else "--no-remove --only-upgrade -s install " + target + " && " + isolated + "--no-remove --only-upgrade -y install " + target)}]
            elif distro == "debian" and codename in {"bookworm", "trixie"}:
                setup = "PATCHDIR=$(mktemp -d /var/tmp/patch-desk.XXXXXX) && chmod 755 \"$PATCHDIR\" && mkdir -p \"$PATCHDIR/lists/partial\" && printf '%s\\n' " + q("deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://deb.debian.org/debian " + codename + " main") + " " + q("deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://deb.debian.org/debian " + codename + "-updates main") + " " + q("deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://security.debian.org/debian-security " + codename + "-security main") + " > \"$PATCHDIR/sources.list\" && "
                isolated = apt + '-o Dir::Etc::sourcelist="$PATCHDIR/sources.list" -o Dir::Etc::sourceparts=- -o Dir::State::lists="$PATCHDIR/lists" '
                fallback = [{"name": "مخزن رسمی موقت Debian", "command": setup + isolated + "-o APT::Update::Error-Mode=any update && " + isolated + ("--no-remove -s upgrade && " + isolated + "--no-remove -y upgrade" if mode == "system" else "--no-remove --only-upgrade -s install " + target + " && " + isolated + "--no-remove --only-upgrade -y install " + target)}]
        else:
            warnings.append("اطلاعیه AlmaLinux در ۲۱ اکتبر ۲۰۲۶، وصله‌ها را در حال آماده‌سازی اعلام کرده است؛ مخزن سالم هم ممکن است هنوز وصله نداشته باشد. وضعیت vendor باید قبل از تأیید رفع CVE تازه‌سازی شود؛ مخزن testing خودکار فعال نمی‌شود.")
            dnf = "dnf --setopt=retries=3 --setopt=timeout=30 --setopt=gpgcheck=1 "
            steps.extend([{"name": "به‌روزرسانی metadata", "command": dnf + "makecache --refresh", "repository": True},
                          {"name": "نصب به‌روزرسانی‌ها بدون allowerasing", "command": dnf + "-y upgrade " + (target if mode == "php" else ""), "package_phase": True}])
            # Official fallback preserves module selection; no reset/switch of PHP streams.
            if inventory["os"].get("VERSION_ID", "").split(".")[0] in {"8", "9", "10"} and all(not p.startswith(("php7", "php8")) for p in packages):
                official = dnf + "--disablerepo='*' '--repofrompath=patch-baseos,https://repo.almalinux.org/almalinux/$releasever/BaseOS/$basearch/os/' '--repofrompath=patch-appstream,https://repo.almalinux.org/almalinux/$releasever/AppStream/$basearch/os/' --enablerepo=patch-baseos --enablerepo=patch-appstream "
                fallback = [{"name": "مخازن رسمی موقت AlmaLinux؛ حفظ بررسی امضا", "command": official + "makecache --refresh && " + official + "-y upgrade " + (target if mode == "php" else "")}]
        for unit in inventory["services"]:
            if re.fullmatch(r"(php[a-zA-Z0-9.-]*fpm|apache2|httpd)\.service", unit):
                steps.append({"name": "راه‌اندازی مجدد " + unit, "command": "systemctl restart " + q(unit) + " && systemctl is-active --quiet " + q(unit)})
        if not inventory["services"] and packages:
            warnings.append("هیچ سرویس PHP-FPM/Apache در حال اجرا شناسایی نشد؛ اعمال وصله بر پردازش وب قابل تأیید نیست.")
    else:
        raise ValueError("اجرای میزبان برای Ubuntu، Debian و AlmaLinux پشتیبانی می‌شود؛ شناسایی سایر لینوکس‌ها ممکن است.")
    if mode == "system":
        warnings.append("به‌روزرسانی همه بسته‌ها ممکن است سرویس‌های دیگر را هم restart کند؛ ارتقای نسخه توزیع، reboot و حذف بسته انجام نمی‌شود.")
    warnings.extend(["آرشیو تنظیمات جای snapshot یا backup داده و برنامه را نمی‌گیرد. پیش از اجرا مسیر بازیابی مستقل داشته باشید.", "قاعده‌های CVE ثبت‌شده مربوط به ۲۱ اکتبر ۲۰۲۶ هستند؛ backportهای جدید و مخازن شخص ثالث به تأیید سازنده نیاز دارند."])
    return {"digest": inventory_digest(inventory), "steps": steps, "fallback": fallback if options.get("official_fallback") else [], "options": options, "warnings": warnings,
            "sources": ["https://www.php.net/archive/2026.php", "https://ubuntu.com/security/notices/USN-8948-1", "https://security-tracker.debian.org/tracker/CVE-2026-109619", "https://almalinux.org/blog/2026-10-21-php2shell-cve-2026-109618-cve-2026-109619/", "https://repo.almalinux.org/", "https://archive.ubuntu.com/"]}


def assess(inventory, remote):
    evidence = []
    distro, release = inventory["os"].get("ID"), inventory["os"].get("VERSION_ID")
    for p in inventory["packages"]:
        if is_php_meta(p):
            continue
        # Only PHP core packages determine remediation; extensions have independent versions.
        if not re.fullmatch(r"(?:php(?:\d\.\d)?-(?:cli|fpm|cgi|common)|php|libapache2-mod-php\d\.\d)", p["name"].split(":")[0]):
            continue
        version = re.search(r"(?:\d+:)?(\d+\.\d+\.\d+)", p["version"])
        status = upstream_status(version.group(1)) if version else "unknown"
        if distro == "ubuntu" and release in UBUNTU:
            branch, minimum = UBUNTU[release]
            # Vendor identity requires the complete Ubuntu revision as well as branch.
            if branch in p["name"] and "ubuntu" in p["version"]:
                r = remote.run("dpkg --compare-versions " + q(p["version"]) + " ge " + q(minimum), timeout=20)
                if not r.code:
                    status = "fixed-ubuntu-baseline"
        evidence.append({**p, "status": status})
    versions = re.findall(r"PHP (\d+\.\d+\.\d+)", inventory["runtime"])
    result = {"packages": evidence, "runtime_versions": versions, "containers": inventory["containers"],
            "discovery_errors": ["بررسی کانتینرهای Docker کامل نشد؛ دسترسی Docker/sudo بررسی شود."] if inventory.get("docker_error") else [],
            "conclusion": "package-evidence-only" if evidence and all(e["status"].startswith("fixed-") for e in evidence) else "needs-vendor-evidence",
            "notice": "وضعیت بسته جای آزمون سلامت برنامه یا اثبات رفع همه نصب‌ها را نمی‌گیرد. برای AlmaLinux/backport شخص ثالث، تأیید vendor جداگانه لازم است."}
    result["summary"] = assessment_summary(result)
    return result


def assessment_summary(assessment):
    packages = [p for p in assessment.get("packages", []) if not is_php_meta(p)]
    versions = assessment.get("runtime_versions", [])
    containers = [c for c in assessment.get("containers", []) if c.get("php")]
    known = bool(packages or versions or containers)
    if not known and not assessment.get("discovery_errors"):
        return {"update_required": None, "title": "PHP شناسایی نشد؛ آپدیتی انجام نشد", "reason": "در بسته‌ها، مسیرهای معمول و کانتینرهای بررسی‌شده PHP قابل ارزیابی پیدا نشد. این نتیجه نه خطای آپدیت است و نه اثبات نبود PHP در نصب سفارشی.", "versions": [], "targets": [], "scope": "فقط مسیرهای بررسی‌شده؛ وضعیت نصب سفارشی نامشخص است."}
    package_fixed = all(p.get("status", "").startswith("fixed-") for p in packages)
    def covered_runtime(v):
        if upstream_status(v) == "fixed-upstream":
            return True
        return any(p.get("status", "").startswith("fixed-") and re.search(r"(?:^|:|[^0-9])" + re.escape(v) + r"(?:$|[^0-9.])", p.get("version", "")) for p in packages)
    safe = known and not assessment.get("discovery_errors") and package_fixed and all(covered_runtime(v) for v in versions) and all(upstream_status(c["php"]) == "fixed-upstream" for c in containers)
    detected = list(dict.fromkeys(versions + [m.group(1) for p in packages if (m := re.search(r"(\d+\.\d+\.\d+)", p.get("version", "")))] + [c["php"] for c in containers]))
    targets = list(dict.fromkeys(FIXED.get(".".join(v.split(".")[:2]), "نسخه پشتیبانی‌شده یا وصله معتبر سازنده") for v in detected))
    return {"update_required": not safe,
            "title": "آپدیت لازم نیست" if safe else "آپدیت لازم است",
            "reason": "نسخه‌های PHP شناسایی‌شده، شواهد اصلاح این دو CVE را دارند." if safe else " ".join(assessment["discovery_errors"]) if assessment.get("discovery_errors") else "ایمنی نسخه فعلی تأیید نشده است؛ به نسخه اصلاح‌شده یا بسته دارای وصله معتبر سازنده به‌روزرسانی کنید." if known else "PHP قابل ارزیابی پیدا نشد؛ تا شناسایی کامل، وضعیت امن تأیید نمی‌شود و بررسی/به‌روزرسانی لازم است.",
            "versions": detected, "targets": targets,
            "scope": "این نتیجه فقط PHPهای شناسایی‌شده و همین دو CVE را پوشش می‌دهد."}
