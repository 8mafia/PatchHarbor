#!/usr/bin/env bash
set -Eeuo pipefail
umask 027

APP_DIR=/opt/patch-desk
STATE_DIR=/var/lib/patch-desk
SERVICE=patch-desk
SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
DRY_RUN=0

usage() {
  cat <<'HELP'
Patch Desk Linux installer
Usage: sudo bash install.sh [--dry-run]
Supported controller: Ubuntu 24.04+, Debian 12+, AlmaLinux 9/10.
Requires systemd. Fresh installations only; existing files are never overwritten.
Installs: /opt/patch-desk; private state: /var/lib/patch-desk
Listens only on 127.0.0.1:8765. Connect using an SSH tunnel.
This installs the controller only. It does NOT patch any remote server.
HELP
}

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --help|-h) usage; exit 0 ;;
    *) printf 'Unknown argument: %s\n' "$arg" >&2; usage; exit 2 ;;
  esac
done
for file in app.py engine.py reporting.py requirements-lock.txt static/index.html static/help.html docs/manual-patching.fa.md; do
  [[ -f "$SOURCE_DIR/$file" ]] || { printf 'Missing source: %s\n' "$file" >&2; exit 1; }
done
if (( DRY_RUN )); then
  usage
  printf '\nPlan: install Python prerequisites; create unprivileged patchdesk user; copy allowlisted source; create venv; install locked requirements; register and start loopback-only systemd service.\n'
  exit 0
fi
[[ $(id -u) == 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
[[ -d /run/systemd/system ]] || { echo 'A running systemd installation is required.' >&2; exit 1; }
[[ ! -e "$APP_DIR" && ! -e "$STATE_DIR" && ! -e /etc/systemd/system/patch-desk.service ]] || { echo 'Existing installation/state detected. Refusing to overwrite. See docs/installation.fa.md.' >&2; exit 1; }
[[ -r /etc/os-release ]] || { echo 'Cannot identify distribution.' >&2; exit 1; }
. /etc/os-release
PYTHON=python3
case "${ID:-}:${VERSION_ID%%.*}" in
  ubuntu:24|ubuntu:25|ubuntu:26|debian:12|debian:13)
    apt-get update -o APT::Update::Error-Mode=any
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 python3-venv python3-pip ca-certificates curl
    ;;
  almalinux:9)
    dnf install -y python3.11 python3.11-pip ca-certificates curl
    PYTHON=python3.11
    ;;
  almalinux:10)
    dnf install -y python3 python3-pip ca-certificates curl
    ;;
  *) echo 'Unsupported controller OS. Use a documented supported OS or the manual Python installation.' >&2; exit 1 ;;
esac
"$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' || { echo 'Python 3.11+ is required.' >&2; exit 1; }
"$PYTHON" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",8765)); s.close()' || { echo 'Port 8765 is already in use. Stop and inspect the existing listener before installing.' >&2; exit 1; }
getent passwd patchdesk >/dev/null && { echo 'User patchdesk already exists; inspect it before installing.' >&2; exit 1; }
useradd --system --user-group --home-dir "$STATE_DIR" --shell /usr/sbin/nologin patchdesk
install -d -m 0755 "$APP_DIR" "$APP_DIR/static" "$APP_DIR/docs"
install -d -m 0700 -o patchdesk -g patchdesk "$STATE_DIR"
for file in app.py engine.py reporting.py requirements.txt requirements-lock.txt README.md; do
  install -m 0644 "$SOURCE_DIR/$file" "$APP_DIR/$file"
done
for file in index.html help.html style.css app.js Vazirmatn.woff2 FONT-LICENSE.txt; do
  install -m 0644 "$SOURCE_DIR/static/$file" "$APP_DIR/static/$file"
done
for file in manual-patching.fa.md installation.fa.md usage.fa.md; do
  install -m 0644 "$SOURCE_DIR/docs/$file" "$APP_DIR/docs/$file"
done
umask 022
"$PYTHON" -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/python" -m pip install --disable-pip-version-check -r "$APP_DIR/requirements-lock.txt"
umask 027
cat > /etc/systemd/system/patch-desk.service <<'UNIT'
[Unit]
Description=Patch Desk local SSH patch controller
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=patchdesk
Group=patchdesk
WorkingDirectory=/opt/patch-desk
Environment=PATCH_DESK_DATA_DIR=/var/lib/patch-desk
Environment=PATCH_DESK_PORT=8765
Environment=PYTHONDONTWRITEBYTECODE=1
Environment=PYTHONUNBUFFERED=1
ExecStart=/opt/patch-desk/.venv/bin/python /opt/patch-desk/app.py
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/patch-desk
CapabilityBoundingSet=
RestrictSUIDSGID=true
ProtectKernelTunables=true
ProtectControlGroups=true
ProtectKernelModules=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now "$SERVICE"
ready=0
for attempt in {1..20}; do
  if systemctl is-active --quiet "$SERVICE" && curl --silent --fail --max-time 2 http://127.0.0.1:8765/ >/dev/null; then ready=1; break; fi
  sleep 1
done
if (( ! ready )); then
  systemctl stop "$SERVICE"
  echo 'HTTP readiness check failed; service stopped. Files and state preserved. Inspect: journalctl -u patch-desk -n 80' >&2
  exit 1
fi
printf '\nInstalled. From your computer: ssh -N -L 8765:127.0.0.1:8765 USER@CONTROLLER\nThen open http://127.0.0.1:8765\nCheck service: systemctl status patch-desk\nNo remote server was patched by the installer.\n'
