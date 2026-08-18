#!/usr/bin/env bash
#
# deploy_rpi.sh — deploy the fake PLC node to a Raspberry Pi (or any Debian
# based SSH host) on an isolated laboratory network.
#
# Run it directly (the file carries the executable bit):
#     scripts/deploy_rpi.sh --host 192.168.50.21
# or explicitly through bash, which works even if the bit was lost in transit
# (for example after unzipping on a filesystem without POSIX permissions):
#     bash scripts/deploy_rpi.sh --host 192.168.50.21
#
# What it does on the remote host:
#   * syncs the project, excluding VCS metadata, virtualenvs, caches, logs,
#     packet captures, private keys and evidence archives
#   * creates a Python virtual environment and installs the project package
#   * builds the native C++ components
#   * installs a *user-level* systemd unit that runs the fake PLC unprivileged
#
# What it deliberately does NOT do:
#   * run anything as root
#   * install or start the FastAPI controller (it has no authentication)
#   * copy signing keys or generate any key material
#   * open any firewall port
#
# Authorized laboratory research only. Never point this at production ICS
# equipment or at a host reachable from an operational network.

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
SSH_USER="pi"
DEST_DIR=""
MODBUS_HOST="127.0.0.1"
MODBUS_PORT="5020"
POLL_INTERVAL="30"
SERVICE_NAME="ics-fake-plc"
START_SERVICE="no"
DRY_RUN="no"
REMOTE_HOST=""
# Post-quantum evidence sealing. Disabled unless the operator asks for it,
# and even then only with a key they provisioned themselves.
PQC_MODE="disabled"
PQC_NODE_ID=""
PQC_KEY_ID=""
PQC_PRIVATE_KEY=""

# Paths never copied to the deception node. Private keys and evidence archives
# are listed explicitly: a signing key must be generated on the node itself and
# must never travel from a workstation.
EXCLUDES=(
    '.git/'
    '.github/'
    '.venv/'
    'venv/'
    '__pycache__/'
    '.pytest_cache/'
    '.ruff_cache/'
    '.mypy_cache/'
    'build/'
    'dist/'
    '*.egg-info/'
    'runtime/'
    'logs/'
    '*.log'
    '*.jsonl'
    '*.pcap'
    '*.pcapng'
    '*.cap'
    '.env'
    'keys/'
    '*.pem'
    '*.key'
    'id_rsa*'
    '*.pqcarch'
    'archives/'
    'benchmarks/'
    'config/controller.json'
)

usage() {
    cat <<'USAGE'
Usage: scripts/deploy_rpi.sh --host HOST [options]
   or: bash scripts/deploy_rpi.sh --host HOST [options]

Required:
  --host HOST            Raspberry Pi hostname or IP address

Options:
  --user USER            SSH user                     (default: pi)
  --dest DIR             Remote destination directory (default: /home/<user>/ics-deception)
  --modbus-host HOST     Modbus honeypot host to poll (default: 127.0.0.1)
  --modbus-port PORT     Modbus honeypot port         (default: 5020)
  --interval SECONDS     Seconds between polls        (default: 30)
  --service-name NAME    systemd user unit name       (default: ics-fake-plc)
  --start                Enable and start the unit immediately (default: install only)
  --dry-run              Print the deployment plan, the exclusion list and the
                         remote script, then exit without contacting the host
  -h, --help             Show this help

Post-quantum evidence sealing (all optional, disabled by default):
  --pqc-mode MODE        disabled | sign | dual | verify-only  (default: disabled)
  --pqc-node-id ID       Node identity written into every signed record
  --pqc-key-id ID        Key identifier written into every signed record
  --pqc-private-key PATH Path to a PRE-PROVISIONED private key on THIS machine.
                         It is installed with mode 0600 on the node. This script
                         never generates a signing key: create one on the node
                         with 'ics-pqc-evidence generate-key' instead.

Example:
  scripts/deploy_rpi.sh --host 192.168.50.21 --user pi \
      --modbus-host 192.168.50.10 --modbus-port 5020 --start

Preview without touching the network:
  scripts/deploy_rpi.sh --host 192.168.50.21 --dry-run

With evidence sealing, using a key you already provisioned:
  scripts/deploy_rpi.sh --host 192.168.50.21 --pqc-mode dual \
      --pqc-node-id rpi-honeypot-01 --pqc-key-id rpi-honeypot-01-2026-01 \
      --pqc-private-key ./keys/rpi-honeypot-01.key
USAGE
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [ "$#" -gt 0 ]; do
    case "$1" in
        --host)         REMOTE_HOST="${2:-}"; shift 2 ;;
        --user)         SSH_USER="${2:-}"; shift 2 ;;
        --dest)         DEST_DIR="${2:-}"; shift 2 ;;
        --modbus-host)  MODBUS_HOST="${2:-}"; shift 2 ;;
        --modbus-port)  MODBUS_PORT="${2:-}"; shift 2 ;;
        --interval)     POLL_INTERVAL="${2:-}"; shift 2 ;;
        --service-name) SERVICE_NAME="${2:-}"; shift 2 ;;
        --start)        START_SERVICE="yes"; shift ;;
        --dry-run)      DRY_RUN="yes"; shift ;;
        --pqc-mode)         PQC_MODE="${2:-}"; shift 2 ;;
        --pqc-node-id)      PQC_NODE_ID="${2:-}"; shift 2 ;;
        --pqc-key-id)       PQC_KEY_ID="${2:-}"; shift 2 ;;
        --pqc-private-key)  PQC_PRIVATE_KEY="${2:-}"; shift 2 ;;
        -h|--help)      usage; exit 0 ;;
        *)              echo "error: unknown option '$1'" >&2; usage >&2; exit 2 ;;
    esac
done

if [ -z "$REMOTE_HOST" ]; then
    echo "error: --host is required" >&2
    usage >&2
    exit 2
fi
if [ -z "$SSH_USER" ]; then
    echo "error: --user must not be empty" >&2
    exit 2
fi
if [ -z "$DEST_DIR" ]; then
    DEST_DIR="/home/${SSH_USER}/ics-deception"
fi
case "$DEST_DIR" in
    /*) : ;;
    *)  echo "error: --dest must be an absolute path" >&2; exit 2 ;;
esac
if [ -z "$SERVICE_NAME" ]; then
    echo "error: --service-name must not be empty" >&2
    exit 2
fi

# Reject zero, negative and non-numeric values rather than silently accepting
# a port of 0 or a poll interval of 0 that would spin the node's CPU.
case "$MODBUS_PORT" in
    ''|*[!0-9]*) echo "error: --modbus-port must be a positive integer" >&2; exit 2 ;;
esac
if [ "$MODBUS_PORT" -lt 1 ] || [ "$MODBUS_PORT" -gt 65535 ]; then
    echo "error: --modbus-port must be in 1..65535" >&2
    exit 2
fi
case "$POLL_INTERVAL" in
    ''|*[!0-9]*) echo "error: --interval must be a positive integer" >&2; exit 2 ;;
esac
if [ "$POLL_INTERVAL" -lt 1 ]; then
    echo "error: --interval must be greater than zero" >&2
    exit 2
fi

case "$PQC_MODE" in
    disabled|sign|dual|verify-only) : ;;
    *) echo "error: --pqc-mode must be disabled, sign, dual or verify-only" >&2; exit 2 ;;
esac

if [ "$PQC_MODE" = "sign" ] || [ "$PQC_MODE" = "dual" ]; then
    if [ -z "$PQC_NODE_ID" ] || [ -z "$PQC_KEY_ID" ] || [ -z "$PQC_PRIVATE_KEY" ]; then
        echo "error: --pqc-mode '$PQC_MODE' requires --pqc-node-id, --pqc-key-id and" >&2
        echo "       --pqc-private-key. This script never generates a signing key." >&2
        exit 2
    fi
    if [ ! -f "$PQC_PRIVATE_KEY" ]; then
        echo "error: private key not found: ${PQC_PRIVATE_KEY}" >&2
        exit 2
    fi
    # A key readable by anyone else is a key that must be replaced, not deployed.
    key_mode="$(stat -c '%a' "$PQC_PRIVATE_KEY" 2>/dev/null || echo '')"
    case "$key_mode" in
        600|400) : ;;
        '')  echo "warning: cannot check permissions on ${PQC_PRIVATE_KEY}" >&2 ;;
        *)   echo "error: ${PQC_PRIVATE_KEY} has mode ${key_mode}; it must be 600 or 400." >&2
             echo "       Fix with: chmod 600 ${PQC_PRIVATE_KEY}" >&2
             exit 2 ;;
    esac
fi

# Where the key will live on the node. Derived here so both the dry-run plan and
# the systemd unit refer to exactly the same path.
PQC_PRIVATE_KEY_NAME=""
PQC_KEY_PATH=""
if [ -n "$PQC_PRIVATE_KEY" ]; then
    PQC_PRIVATE_KEY_NAME="$(basename "$PQC_PRIVATE_KEY")"
    PQC_KEY_PATH="${DEST_DIR}/keys/${PQC_PRIVATE_KEY_NAME}"
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${SSH_USER}@${REMOTE_HOST}"

# ---------------------------------------------------------------------------
# The remote script — a single source of truth, printed verbatim by --dry-run
# and piped to the remote shell otherwise. Values arrive as environment
# variables, so this stays a literal (quoted) heredoc with no local expansion.
# ---------------------------------------------------------------------------
REMOTE_SCRIPT="$(cat <<'REMOTE'
set -euo pipefail

echo "==> Remote user: $(id -un) (uid $(id -u))"
if [ "$(id -u)" -eq 0 ]; then
    echo "error: refusing to deploy as root; use an unprivileged SSH user" >&2
    exit 1
fi

cd "$DEST_DIR"

# --- Python environment ---------------------------------------------------
echo "==> Creating virtual environment"
python3 -m venv .venv
# shellcheck disable=SC1091
. .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel

echo "==> Installing the ics-deception package"
# Installs from pyproject.toml, so all project metadata and runtime
# dependencies come along; no reliance on a stray requirements.txt.
python -m pip install .

# --- Native components ----------------------------------------------------
if command -v g++ >/dev/null 2>&1 && command -v make >/dev/null 2>&1; then
    echo "==> Building native C++ components"
    make -C src/native BUILD_DIR="${DEST_DIR}/build" all
else
    echo "==> WARNING: g++/make not found; skipping native build."
    echo "    Install them with: sudo apt-get install -y build-essential"
fi

# --- User-level systemd unit ---------------------------------------------
echo "==> Installing user systemd unit '${SERVICE_NAME}'"
mkdir -p "${HOME}/.config/systemd/user"
# Runtime state may contain attacker-supplied data and, when sealing is on, the
# chain state. Owner-only from the moment it is created.
mkdir -p "${DEST_DIR}/runtime"
chmod 0700 "${DEST_DIR}/runtime"
mkdir -p "${DEST_DIR}/runtime/pqc"
chmod 0700 "${DEST_DIR}/runtime/pqc"

if [ "$PQC_MODE" != "disabled" ]; then
    echo "==> Configuring PQC evidence mode '${PQC_MODE}'"
    if [ -n "$PQC_PRIVATE_KEY_NAME" ]; then
        mkdir -p "${DEST_DIR}/keys"
        chmod 0700 "${DEST_DIR}/keys"
        # The key arrived in a staging path; move it into place owner-only.
        mv "${DEST_DIR}/.incoming-key" "${DEST_DIR}/keys/${PQC_PRIVATE_KEY_NAME}"
        chmod 0600 "${DEST_DIR}/keys/${PQC_PRIVATE_KEY_NAME}"
        echo "    installed private key: ${DEST_DIR}/keys/${PQC_PRIVATE_KEY_NAME} (mode 0600)"
    fi
fi

cat > "${HOME}/.config/systemd/user/${SERVICE_NAME}.service" <<UNIT
[Unit]
Description=ICS Deception Framework - fake PLC node (research prototype)
Documentation=https://github.com/N-Bermparis/ICS-Deception-Framework
After=network-online.target

[Service]
Type=simple
WorkingDirectory=${DEST_DIR}
Environment=ICS_DECEPTION_RUNTIME_DIR=${DEST_DIR}/runtime
Environment=ICS_PQC_EVIDENCE_MODE=${PQC_MODE}
Environment=ICS_PQC_NODE_ID=${PQC_NODE_ID}
Environment=ICS_PQC_KEY_ID=${PQC_KEY_ID}
Environment=ICS_PQC_PRIVATE_KEY=${PQC_KEY_PATH}
Environment=ICS_PQC_EVIDENCE_LOG=${DEST_DIR}/runtime/pqc/evidence.jsonl
Environment=ICS_PQC_STATE=${DEST_DIR}/runtime/pqc/state.json
Environment=ICS_PQC_PRODUCTION=1
ExecStart=${DEST_DIR}/.venv/bin/ics-fake-plc --target-host ${MODBUS_HOST} --target-port ${MODBUS_PORT} --interval ${POLL_INTERVAL}
Restart=on-failure
RestartSec=10

# Hardening: this unit runs as the invoking (unprivileged) user and can never
# gain privileges, not even through a setuid binary.
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=${DEST_DIR}/runtime
RestrictSUIDSGID=true
MemoryDenyWriteExecute=true
LockPersonality=true

[Install]
WantedBy=default.target
UNIT

chmod 0644 "${HOME}/.config/systemd/user/${SERVICE_NAME}.service"
systemctl --user daemon-reload

if [ "$START_SERVICE" = "yes" ]; then
    echo "==> Enabling and starting ${SERVICE_NAME}"
    systemctl --user enable --now "${SERVICE_NAME}.service"
    sleep 2
    systemctl --user --no-pager status "${SERVICE_NAME}.service" || true
else
    echo "==> Unit installed but NOT started (pass --start to enable it)."
    echo "    Start manually with: systemctl --user enable --now ${SERVICE_NAME}"
fi

echo
echo "==> Deployment summary"
echo "    destination     : ${DEST_DIR}"
echo "    service         : ${SERVICE_NAME} (user-level, unprivileged)"
echo "    modbus target   : ${MODBUS_HOST}:${MODBUS_PORT} every ${POLL_INTERVAL}s"
echo "    runtime dir     : ${DEST_DIR}/runtime (mode 0700)"
echo "    evidence mode   : ${PQC_MODE}"
if [ "$PQC_MODE" != "disabled" ]; then
    echo "    evidence node   : ${PQC_NODE_ID}"
    echo "    evidence key id : ${PQC_KEY_ID}"
    echo "    private key     : ${PQC_KEY_PATH} (contents never printed)"
    echo "    evidence log    : ${DEST_DIR}/runtime/pqc/evidence.jsonl"
fi
echo "==> NOTE: the FastAPI controller was deliberately not installed or started."
echo "    It has no authentication; run it manually on loopback only."
echo "==> NOTE: this script never generates a signing key. Create one on the node"
echo "    with 'ics-pqc-evidence generate-key', or pass --pqc-private-key."
echo "==> To keep the unit running after logout: sudo loginctl enable-linger $(id -un)"
REMOTE
)"

# ---------------------------------------------------------------------------
# Dry run: show the plan and exit before touching the network
# ---------------------------------------------------------------------------
if [ "$DRY_RUN" = "yes" ]; then
    echo "==> DRY RUN: nothing will be copied, executed or started."
    echo "    target            = ${TARGET}"
    echo "    source            = ${REPO_ROOT}"
    echo "    destination       = ${DEST_DIR}"
    echo "    modbus target     = ${MODBUS_HOST}:${MODBUS_PORT}"
    echo "    poll interval     = ${POLL_INTERVAL}s"
    echo "    service name      = ${SERVICE_NAME}"
    echo "    start after install = ${START_SERVICE}"
    echo "    pqc evidence mode   = ${PQC_MODE}"
    if [ "$PQC_MODE" != "disabled" ]; then
        echo "    pqc node id         = ${PQC_NODE_ID}"
        echo "    pqc key id          = ${PQC_KEY_ID}"
        echo "    pqc private key     = ${PQC_PRIVATE_KEY} -> ${PQC_KEY_PATH}"
        echo "    (the key's CONTENTS are never printed or logged)"
    fi
    echo
    echo "==> Excluded from the sync:"
    for pattern in "${EXCLUDES[@]}"; do
        echo "    - ${pattern}"
    done
    echo
    echo "==> Remote script that would run:"
    printf '%s\n' "$REMOTE_SCRIPT"
    exit 0
fi

echo "==> Deploying to ${TARGET}:${DEST_DIR}"
echo "    Modbus target: ${MODBUS_HOST}:${MODBUS_PORT} every ${POLL_INTERVAL}s"

# ---------------------------------------------------------------------------
# 1. Sync the project (metadata included, junk and secrets excluded)
# ---------------------------------------------------------------------------
# shellcheck disable=SC2029  # DEST_DIR is deliberately expanded locally: the
# destination is chosen by the operator here, not by the remote shell.
ssh "$TARGET" "mkdir -p '${DEST_DIR}'"

if command -v rsync >/dev/null 2>&1; then
    rsync_args=(-az --delete)
    for pattern in "${EXCLUDES[@]}"; do
        rsync_args+=(--exclude "$pattern")
    done
    rsync "${rsync_args[@]}" "${REPO_ROOT}/" "${TARGET}:${DEST_DIR}/"
else
    echo "==> rsync not found; falling back to a filtered tar over ssh"
    tar_args=()
    for pattern in "${EXCLUDES[@]}"; do
        tar_args+=(--exclude="${pattern%/}")
    done
    # shellcheck disable=SC2029  # local expansion of DEST_DIR is intended
    tar -C "$REPO_ROOT" "${tar_args[@]}" -czf - . |
        ssh "$TARGET" "tar -C '${DEST_DIR}' -xzf -"
fi

# ---------------------------------------------------------------------------
# 2. Remote build and install (unprivileged, user-level systemd)
# ---------------------------------------------------------------------------
if [ -n "$PQC_PRIVATE_KEY" ]; then
    echo "==> Installing the pre-provisioned private key (contents never printed)"
    # shellcheck disable=SC2029  # local expansion of DEST_DIR is intended
    scp -q "$PQC_PRIVATE_KEY" "${TARGET}:${DEST_DIR}/.incoming-key"
fi

# shellcheck disable=SC2029  # these values come from this script's options and
# are expanded locally on purpose, then read as environment variables remotely.
printf '%s\n' "$REMOTE_SCRIPT" | ssh "$TARGET" \
    "DEST_DIR='${DEST_DIR}' \
     MODBUS_HOST='${MODBUS_HOST}' \
     MODBUS_PORT='${MODBUS_PORT}' \
     POLL_INTERVAL='${POLL_INTERVAL}' \
     SERVICE_NAME='${SERVICE_NAME}' \
     START_SERVICE='${START_SERVICE}' \
     PQC_MODE='${PQC_MODE}' \
     PQC_NODE_ID='${PQC_NODE_ID}' \
     PQC_KEY_ID='${PQC_KEY_ID}' \
     PQC_PRIVATE_KEY_NAME='${PQC_PRIVATE_KEY_NAME}' \
     PQC_KEY_PATH='${PQC_KEY_PATH}' \
     bash -s"

echo "==> Deployment finished for ${TARGET}"
echo "    Logs:   ${DEST_DIR}/runtime/"
echo "    Status: ssh ${TARGET} 'systemctl --user status ${SERVICE_NAME}'"
