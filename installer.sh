#!/usr/bin/env bash
#
# installer.sh — install a prebuilt concert binary as a confined systemd
# service that runs under SELinux enforcing mode.
#
# The binary is taken from /home/rocky/concert-linux-amd64, where the
# deployment pipeline uploads it. Upload a new build there and re-run this
# script to upgrade.
#
# Usage:
#
#   sudo bash installer.sh                                   # installs /home/rocky/concert-linux-amd64
#   sudo CONCERT_BINARY=/tmp/concert bash installer.sh       # install a binary from somewhere else
#   sudo CONCERT_SHA256=<sum> bash installer.sh              # refuse a binary with a different checksum
#   sudo bash installer.sh uninstall                         # remove service, policy, port labels
#   sudo PURGE=1 bash installer.sh uninstall                 # also remove /etc/concert, /var/lib/concert, the user
#
# Settings (first install only; afterwards edit /etc/concert/concert.env and
# re-run this script so port labels match):
#
#   sudo CONCERT_LISTEN=0.0.0.0:443 \
#        CONCERT_UPSTREAM=http://127.0.0.1:8080 \
#        CONCERT_CAPACITY=20 \
#        CONCERT_TLS_DOMAINS=example.com,www.example.com \
#        CONCERT_TLS_EMAIL=ops@example.com \
#        CONCERT_TLS_STAGING=true \
#        OPEN_FIREWALL=1 \
#        bash installer.sh
#
# Other knobs:
#   CONCERT_BINARY=/path/to/concert   binary to install (default: /home/rocky/concert-linux-amd64,
#                                     then the installed copy)
#   CONCERT_SHA256=<sum>              refuse to install a binary with a different checksum
#   CONCERT_PORTAL_LISTEN / CONCERT_PORTAL_ALLOW   admin portal address and CIDRs
#   INSTALL_DEPS=0                    don't dnf-install missing SELinux tooling
#
# What it does:
#   1. verifies the binary and installs a root-owned copy
#   2. compiles and loads an SELinux module that confines concert in concert_t
#   3. labels the listen, portal and upstream ports
#   4. creates /var/lib/concert for the Let's Encrypt certificate cache and
#      /var/lib/concert/data for settings.json and bans.json
#   5. writes /etc/concert/concert.env (secrets generated once, kept on upgrade)
#   6. installs a hardened systemd unit, starts it, and verifies the process
#      is running in concert_t with no AVC denials
#
# concert reads every setting from CONCERT_* environment variables, so the
# unit passes no flags: /etc/concert/concert.env is the whole configuration,
# except for values changed in the admin portal, which concert saves to
# /var/lib/concert/data/settings.json and which take priority over the env file.
#
# Requires RHEL/Alma/Rocky 8+, CentOS Stream, or Fedora (kernel with the
# process2 class, needed for NoNewPrivileges domain transitions).
# ─────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Paths ────────────────────────────────────────────────────────────

DEFAULT_BINARY=/home/rocky/concert-linux-amd64
BIN=/usr/local/bin/concert
ETC=/etc/concert
ENV_FILE="$ETC/concert.env"
STATE="$ETC/.installer-state"
STATE_DIR=/var/lib/concert
DATA_DIR="$STATE_DIR/data"
UNIT=/etc/systemd/system/concert.service
SVC_USER=concert
MODULE=concert
DEVEL_MAKEFILE=/usr/share/selinux/devel/Makefile

# ── Settings ─────────────────────────────────────────────────────────

LISTEN="${CONCERT_LISTEN:-0.0.0.0:8080}"
UPSTREAM="${CONCERT_UPSTREAM:-http://127.0.0.1:3000}"
CAPACITY="${CONCERT_CAPACITY:-${CONCERT_CAP:-10}}"
PORTAL_LISTEN="${CONCERT_PORTAL_LISTEN:-127.0.0.1:8081}"
PORTAL_ALLOW="${CONCERT_PORTAL_ALLOW:-127.0.0.1/32,::1/128}"
TLS_DOMAINS="${CONCERT_TLS_DOMAINS:-}"
TLS_EMAIL="${CONCERT_TLS_EMAIL:-}"
TLS_STAGING="${CONCERT_TLS_STAGING:-false}"
OPEN_FIREWALL="${OPEN_FIREWALL:-0}"
BINARY_SRC="${CONCERT_BINARY:-}"
BINARY_SHA256="${CONCERT_SHA256:-}"
INSTALL_DEPS="${INSTALL_DEPS:-1}"
PURGE="${PURGE:-0}"

# ── Output helpers ───────────────────────────────────────────────────

if [[ -t 1 ]]; then
    RED=$'\e[31m' GREEN=$'\e[32m' YELLOW=$'\e[33m' DIM=$'\e[2m' BOLD=$'\e[1m' RESET=$'\e[0m'
else
    RED="" GREEN="" YELLOW="" DIM="" BOLD="" RESET=""
fi

log()  { echo "${DIM}==>${RESET} $*"; }
ok()   { echo "${GREEN}✓${RESET} $*"; }
warn() { echo "${YELLOW}⚠${RESET}  $*" >&2; }
die()  { echo "${RED}error:${RESET} $*" >&2; exit 1; }

WORK=""
cleanup() { [[ -n "$WORK" && -d "$WORK" ]] && rm -rf -- "$WORK"; }
trap cleanup EXIT

# ── Guards ───────────────────────────────────────────────────────────

[[ "$(id -u)" -eq 0 ]] || die "run as root (sudo bash installer.sh)"
command -v systemctl &>/dev/null || die "systemd is required"

selinux_active() {
    command -v getenforce &>/dev/null && [[ "$(getenforce)" != "Disabled" ]]
}

# ── Address parsing ──────────────────────────────────────────────────

# "0.0.0.0:8080" / "[::]:8080" / ":8080" -> 8080
port_of_addr() { echo "${1##*:}"; }

# "http://host:3000/path" -> 3000, "https://host" -> 443
port_of_url() {
    local url=$1 scheme rest hostport
    scheme="${url%%://*}"
    rest="${url#*://}"
    hostport="${rest%%/*}"
    if [[ "$hostport" =~ :([0-9]+)$ ]]; then
        echo "${BASH_REMATCH[1]}"
    elif [[ "$scheme" == "https" ]]; then
        echo 443
    else
        echo 80
    fi
}

valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )); }

# Read KEY=value from the env file without sourcing it. EnvironmentFile has
# no trailing-comment syntax, so the value is everything after the "=".
env_get() { sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1; }

state_add() {
    touch "$STATE" && chmod 600 "$STATE"
    grep -qxF "$1" "$STATE" || echo "$1" >> "$STATE"
}

# ── Binary ───────────────────────────────────────────────────────────

# Source binary, in order: CONCERT_BINARY, the pipeline's upload at
# $DEFAULT_BINARY, or the copy already at $BIN (reinstalled in place with
# correct ownership and label).
resolve_binary() {
    local sum

    if [[ -z "$BINARY_SRC" ]]; then
        if [[ -f "$DEFAULT_BINARY" ]]; then
            BINARY_SRC="$DEFAULT_BINARY"
        elif [[ -f "$BIN" ]]; then
            BINARY_SRC="$BIN"
            warn "$DEFAULT_BINARY not found; reinstalling the copy already at $BIN"
        else
            die "no binary found: upload it to $DEFAULT_BINARY or set CONCERT_BINARY=/path/to/concert"
        fi
    fi

    [[ -f "$BINARY_SRC" && -r "$BINARY_SRC" ]] || die "$BINARY_SRC is not a readable file"
    [[ "$(head -c 4 "$BINARY_SRC" | od -An -tx1 | tr -d ' \n')" == "7f454c46" ]] \
        || die "$BINARY_SRC is not an ELF executable"

    sum=$(sha256sum "$BINARY_SRC" | awk '{print $1}')
    if [[ -n "$BINARY_SHA256" && "$sum" != "$BINARY_SHA256" ]]; then
        die "sha256 mismatch for $BINARY_SRC: got $sum, expected $BINARY_SHA256"
    fi
    ok "Using $BINARY_SRC (sha256 $sum)"
}

install_binary() {
    # Always install a fresh root-owned 0755 copy. The uploaded file's owner,
    # mode and SELinux label come from whoever uploaded it, so it is never
    # used as-is. restorecon is what applies concert_exec_t; a plain mv would
    # keep the label the file was created with.
    install -m 0755 -o root -g root "$BINARY_SRC" "$BIN.new"
    mv -f -- "$BIN.new" "$BIN"
    if selinux_active; then
        restorecon -F "$BIN"
        [[ "$(stat -c %C "$BIN")" == *concert_exec_t* ]] \
            || die "$BIN is $(stat -c %C "$BIN"), expected concert_exec_t"
        ok "Installed $BIN ($(stat -c %C "$BIN"))"
    else
        ok "Installed $BIN"
    fi
}

# Proves the service user can execute the installed binary, and reports its
# version. -version exits before reading any configuration.
preflight_exec() {
    local version
    if ! runuser -u "$SVC_USER" -- test -x "$BIN"; then
        echo >&2
        namei -l "$BIN" >&2
        findmnt -T "$BIN" -o TARGET,OPTIONS >&2
        die "user $SVC_USER cannot execute $BIN (directory permissions, file mode, or a noexec mount; see above)"
    fi
    if ! version=$(runuser -u "$SVC_USER" -- "$BIN" -version 2>&1); then
        echo "$version" >&2
        die "$BIN failed to run as $SVC_USER (wrong architecture or a corrupt upload?)"
    fi
    ok "$SVC_USER can execute $BIN (version ${BOLD}${version}${RESET})"
}

# ── SELinux: tooling ─────────────────────────────────────────────────

ensure_selinux_tooling() {
    local missing=()
    command -v semanage &>/dev/null || missing+=(policycoreutils-python-utils)
    [[ -f "$DEVEL_MAKEFILE" ]]     || missing+=(selinux-policy-devel)
    command -v restorecon &>/dev/null || missing+=(policycoreutils)

    (( ${#missing[@]} == 0 )) && return

    if [[ "$INSTALL_DEPS" == "1" ]] && command -v dnf &>/dev/null; then
        log "Installing SELinux tooling: ${missing[*]}"
        dnf install -y "${missing[@]}" >/dev/null
    else
        die "missing packages: ${missing[*]}"
    fi
}

# ── SELinux: policy module ───────────────────────────────────────────

write_policy() {
    local dir=$1
    mkdir -p "$dir"

    cat > "$dir/$MODULE.te" <<'EOF'
policy_module(concert, 1.1.0)

########################################
# Declarations

type concert_t;
type concert_exec_t;
init_daemon_domain(concert_t, concert_exec_t)

type concert_etc_t;
files_config_file(concert_etc_t)

# Let's Encrypt account key and certificates, settings.json and bans.json
# under /var/lib/concert.
type concert_var_lib_t;
files_type(concert_var_lib_t)

# Ports concert may listen on (main listener and admin portal).
type concert_port_t;
corenet_port(concert_port_t)

# Ports concert may connect to as its upstream origin.
type concert_upstream_port_t;
corenet_port(concert_upstream_port_t)

gen_require(`
	type init_t;
	type syslogd_t;
	type http_port_t;
	type http_cache_port_t;
	class process2 { nnp_transition nosuid_transition };
')

########################################
# Local policy

# The unit sets NoNewPrivileges=yes; without this the init_t -> concert_t
# transition is refused and the service fails to start under enforcing.
allow init_t concert_t:process2 { nnp_transition nosuid_transition };

allow concert_t self:capability net_bind_service;
allow concert_t self:process { getsched setsched signal_perms };
allow concert_t self:fifo_file rw_fifo_file_perms;
allow concert_t self:unix_stream_socket create_stream_socket_perms;
allow concert_t self:unix_dgram_socket create_socket_perms;
allow concert_t self:tcp_socket { accept listen create_stream_socket_perms };
allow concert_t self:udp_socket create_socket_perms;
allow concert_t self:netlink_route_socket r_netlink_socket_perms;

# Configuration under /etc/concert
list_dirs_pattern(concert_t, concert_etc_t, concert_etc_t)
read_files_pattern(concert_t, concert_etc_t, concert_etc_t)

# Certificate cache, settings.json and bans.json under /var/lib/concert
files_search_var_lib(concert_t)
manage_dirs_pattern(concert_t, concert_var_lib_t, concert_var_lib_t)
manage_files_pattern(concert_t, concert_var_lib_t, concert_var_lib_t)

# Listening: its own ports, plus the standard web ports (80/443, 8080, ...)
corenet_tcp_bind_generic_node(concert_t)
allow concert_t { concert_port_t http_port_t http_cache_port_t }:tcp_socket name_bind;

# Upstream origin, and the Let's Encrypt API on 443 (http_port_t)
allow concert_t { concert_upstream_port_t http_port_t http_cache_port_t }:tcp_socket name_connect;

# Name resolution, /etc/hosts, CA roots for Let's Encrypt and https upstreams,
# time zones
sysnet_dns_name_resolve(concert_t)
auth_use_nsswitch(concert_t)
files_read_etc_files(concert_t)
miscfiles_read_generic_certs(concert_t)
miscfiles_read_localization(concert_t)

# Go runtime: /proc, somaxconn, THP size in sysfs, cgroup CPU limits
kernel_read_system_state(concert_t)
kernel_read_net_sysctls(concert_t)
dev_read_sysfs(concert_t)
dev_read_urand(concert_t)
fs_search_cgroup_dirs(concert_t)
fs_read_cgroup_files(concert_t)

# stdout/stderr (access log) go to the journal
logging_send_syslog_msg(concert_t)
allow concert_t init_t:unix_stream_socket { getattr ioctl read write };
allow concert_t syslogd_t:unix_stream_socket { getattr ioctl read write };
EOF

    cat > "$dir/$MODULE.fc" <<'EOF'
/usr/local/bin/concert	--	gen_context(system_u:object_r:concert_exec_t,s0)
/etc/concert(/.*)?		gen_context(system_u:object_r:concert_etc_t,s0)
/var/lib/concert(/.*)?		gen_context(system_u:object_r:concert_var_lib_t,s0)
EOF

    cat > "$dir/$MODULE.if" <<'EOF'
## <summary>Concert FIFO waiting room reverse proxy.</summary>
EOF
}

load_policy() {
    local dir="$WORK/selinux"
    log "Compiling SELinux module"
    write_policy "$dir"
    if ! (cd "$dir" && make -f "$DEVEL_MAKEFILE" "$MODULE.pp" >"$dir/build.log" 2>&1); then
        cat "$dir/build.log" >&2
        die "SELinux module failed to compile"
    fi
    semodule -i "$dir/$MODULE.pp"
    ok "Loaded SELinux module ${BOLD}$MODULE${RESET}"
}

# ── SELinux: ports ───────────────────────────────────────────────────

# Most specific type currently assigned to tcp/PORT (exact beats range).
effective_port_type() {
    semanage port -l | awk -v p="$1" '
        $2 == "tcp" {
            for (i = 3; i <= NF; i++) {
                v = $i; gsub(/,/, "", v)
                n = split(v, r, "-")
                lo = r[1] + 0; hi = (n == 2 ? r[2] : r[1]) + 0
                if (p + 0 >= lo && p + 0 <= hi && (best == "" || hi - lo < width)) {
                    best = $1; width = hi - lo
                }
            }
        }
        END { print best }'
}

# label_port PORT WANTED_TYPE [ALREADY_ACCEPTABLE_TYPE...]
label_port() {
    local port=$1 want=$2 cur t
    shift 2
    cur=$(effective_port_type "$port")

    for t in "$want" "$@"; do
        if [[ "$cur" == "$t" ]]; then
            ok "tcp/$port is ${cur}, already permitted"
            return
        fi
    done

    if semanage port -a -t "$want" -p tcp "$port" 2>/dev/null; then
        ok "Labeled tcp/$port as $want"
    else
        warn "tcp/$port was ${cur:-unlabeled}; reassigning it to $want"
        semanage port -m -t "$want" -p tcp "$port"
    fi
    state_add "port $port"
}

# ── User, state directory and configuration ──────────────────────────

ensure_user() {
    if ! getent passwd "$SVC_USER" >/dev/null; then
        useradd --system --user-group --no-create-home \
            --home-dir /nonexistent --shell /sbin/nologin "$SVC_USER"
        ok "Created system user $SVC_USER"
    fi
}

# /var/lib/concert holds the ACME account key and certificates, and
# /var/lib/concert/data holds settings.json and bans.json. The unit's
# StateDirectory= also creates /var/lib/concert and bind-mounts it writable
# past ProtectSystem=strict; doing it here as well lets restorecon label both
# before the first start. Existing settings and bans are never touched. Must
# run after load_policy, when the type exists.
ensure_state_dir() {
    install -d -m 0700 -o "$SVC_USER" -g "$SVC_USER" "$STATE_DIR"
    install -d -m 0700 -o "$SVC_USER" -g "$SVC_USER" "$DATA_DIR"
    if selinux_active; then
        restorecon -RF "$STATE_DIR"
        ok "State directory $STATE_DIR ($(stat -c %C "$STATE_DIR"))"
    else
        ok "State directory $STATE_DIR"
    fi
    local f
    for f in settings.json bans.json; do
        [[ -f "$DATA_DIR/$f" ]] && ok "Keeping existing $DATA_DIR/$f"
    done
    return 0
}

FIRST_INSTALL=0
PORTAL_PASS=""

# Earlier installers wrote CONCERT_CAP and passed it as -cap. concert reads
# capacity from CONCERT_CAPACITY, and the unit no longer passes flags.
migrate_env_file() {
    if grep -q '^CONCERT_CAP=' "$ENV_FILE" && ! grep -q '^CONCERT_CAPACITY=' "$ENV_FILE"; then
        sed -i 's/^CONCERT_CAP=/CONCERT_CAPACITY=/' "$ENV_FILE"
        ok "Renamed CONCERT_CAP to CONCERT_CAPACITY in $ENV_FILE"
    fi
}

# EnvironmentFile has no trailing-comment syntax: anything after the "=" is
# part of the value. Catch the mistake here instead of at startup.
check_env_file() {
    local bad
    bad=$(grep -nE '^[A-Z_]+=[^#]*[[:space:]]#' "$ENV_FILE" || true)
    if [[ -n "$bad" ]]; then
        warn "$ENV_FILE has trailing comments; systemd makes them part of the value:"
        echo "$bad" | sed -E 's/^([0-9]+):([A-Z_]+)=.*/  line \1: \2/' >&2
        die "remove the trailing comments (only whole-line # comments are allowed)"
    fi
}

write_env_file() {
    install -d -m 0750 -o root -g "$SVC_USER" "$ETC"

    if [[ -f "$ENV_FILE" ]]; then
        migrate_env_file
        check_env_file
        ok "Keeping existing $ENV_FILE"
    else
        FIRST_INSTALL=1
        local secret secure_cookie=false
        secret=$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')
        PORTAL_PASS=$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')
        [[ -n "$TLS_DOMAINS" ]] && secure_cookie=true

        ( umask 077
          cat > "$ENV_FILE" <<EOF
# concert settings. concert reads every setting from these CONCERT_*
# variables; run "concert -h" for the full list. Only whole-line comments
# are allowed: systemd makes anything after the "=" part of the value.
# Values changed in the admin portal are saved to
# $DATA_DIR/settings.json and take priority over this file;
# use Reset in the portal to hand a setting back to this file.
# After editing, re-run installer.sh so port labels match, or at least:
#   systemctl restart concert
CONCERT_LISTEN=$LISTEN
CONCERT_UPSTREAM=$UPSTREAM
CONCERT_CAPACITY=$CAPACITY
CONCERT_PORTAL_LISTEN=$PORTAL_LISTEN
CONCERT_PORTAL_ALLOW=$PORTAL_ALLOW
CONCERT_ASSETS=
CONCERT_TRUSTED_PROXIES=127.0.0.1/32,::1/128
CONCERT_ACCESS_LOG=true
CONCERT_API_JSON=true
CONCERT_SECURE_COOKIE=$secure_cookie

# Portal settings and bans (settings.json, bans.json).
CONCERT_DATA_DIR=$DATA_DIR

# Let's Encrypt. A non-empty CONCERT_TLS_DOMAINS serves CONCERT_LISTEN over TLS.
CONCERT_TLS_DOMAINS=$TLS_DOMAINS
CONCERT_TLS_EMAIL=$TLS_EMAIL
CONCERT_TLS_CACHE=$STATE_DIR/acme
CONCERT_TLS_STAGING=$TLS_STAGING

CONCERT_ADMIT_SECRET=$secret
CONCERT_PORTAL_PASS=$PORTAL_PASS
EOF
        )
        chown root:root "$ENV_FILE"
        chmod 0600 "$ENV_FILE"
        ok "Wrote $ENV_FILE"
    fi

    # The env file is authoritative from here on. Unset values fall back to
    # concert's own defaults, which the port checks below must match.
    LISTEN=$(env_get CONCERT_LISTEN);               LISTEN="${LISTEN:-:8080}"
    UPSTREAM=$(env_get CONCERT_UPSTREAM);           UPSTREAM="${UPSTREAM:-http://127.0.0.1:3000}"
    PORTAL_LISTEN=$(env_get CONCERT_PORTAL_LISTEN); PORTAL_LISTEN="${PORTAL_LISTEN:-127.0.0.1:8081}"

    # Ports changed in the portal live in settings.json and win over the env
    # file, so the port labels must follow them.
    settings_override listen        LISTEN
    settings_override upstream      UPSTREAM
    settings_override portal_listen PORTAL_LISTEN

    selinux_active && restorecon -RF "$ETC"
    return 0
}

# settings_override KEY VAR — when settings.json holds a string for KEY, use
# it for VAR. Only flat "key": "value" strings are read, which is all concert
# writes for these keys.
settings_override() {
    local key=$1 var=$2 file="$DATA_DIR/settings.json" val
    [[ -f "$file" ]] || return 0
    val=$(sed -n "s/^[[:space:]]*\"$key\":[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$file" | tail -n 1)
    if [[ -n "$val" ]]; then
        printf -v "$var" '%s' "$val"
        ok "$key=$val (from $file, overrides $ENV_FILE)"
    fi
}

# ── systemd unit ─────────────────────────────────────────────────────

write_unit() {
    local caps=""
    if (( $(port_of_addr "$LISTEN") < 1024 )); then
        caps="CAP_NET_BIND_SERVICE"
    fi

    cat > "$UNIT" <<EOF
[Unit]
Description=Concert FIFO waiting room reverse proxy
Documentation=https://github.com/andreimerlescu/concert
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SVC_USER
Group=$SVC_USER
EnvironmentFile=$ENV_FILE
ExecStart=$BIN
Restart=on-failure
RestartSec=2
LimitNOFILE=65536

# Certificate cache, settings.json and bans.json. ProtectSystem=strict makes
# the filesystem read-only; StateDirectory= is the writable carve-out.
StateDirectory=concert
StateDirectoryMode=0700

# Hardening
NoNewPrivileges=yes
CapabilityBoundingSet=$caps
AmbientCapabilities=$caps
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    ok "Installed $UNIT"
}

# ── Firewall ─────────────────────────────────────────────────────────

open_firewall() {
    [[ "$OPEN_FIREWALL" == "1" ]] || return 0
    if ! systemctl is-active --quiet firewalld; then
        warn "OPEN_FIREWALL=1 but firewalld is not running; skipping"
        return
    fi
    local port
    port=$(port_of_addr "$LISTEN")
    firewall-cmd --quiet --permanent --add-port="$port/tcp"
    firewall-cmd --quiet --reload
    state_add "fw $port"
    ok "Opened tcp/$port in firewalld"
}

# ── Verification ─────────────────────────────────────────────────────

# Matches denials against the confined domain, its files, and systemd's
# pre-exec child, which is named "(concert)" and still runs as init_t.
report_avcs() {
    selinux_active && command -v ausearch &>/dev/null || return 0
    local avcs
    avcs=$(ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null \
        | grep -E 'concert_(t|exec_t|var_lib_t|etc_t)|comm="\(?concert\)?"|name="concert"' || true)
    if [[ -n "$avcs" ]]; then
        warn "SELinux denials involving concert:"
        echo "$avcs" | tail -n 20 >&2
        echo "  Inspect:  ausearch -m AVC -ts recent | audit2why" >&2
        return 1
    fi
    ok "No audited SELinux denials for concert (semodule -DB reveals dontaudit rules; semodule -B restores)"
}

verify() {
    sleep 2
    if ! systemctl is-active --quiet concert; then
        journalctl -u concert -n 30 --no-pager >&2 || true
        report_avcs || true
        die "concert failed to start"
    fi
    ok "concert is running"

    if selinux_active; then
        local pid ctx
        pid=$(systemctl show -p MainPID --value concert)
        ctx=$(ps -o label= -p "$pid" | tr -d ' ')
        if [[ "$ctx" == *:concert_t:* ]]; then
            ok "Process $pid is confined: $ctx"
        else
            warn "Process $pid is running as $ctx, not concert_t"
        fi
    fi

    local port code url domain host
    local insecure=()
    port=$(port_of_addr "$LISTEN")
    domain=$(env_get CONCERT_TLS_DOMAINS)
    domain="${domain%%,*}"
    domain="${domain// /}"

    if [[ -n "$domain" ]]; then
        # The first HTTPS request is what triggers certificate issuance.
        [[ "$(env_get CONCERT_TLS_STAGING)" == "true" ]] && insecure=(-k)
        url="https://$domain:$port/"
        log "Requesting $url (the first request obtains the certificate)"
        code=$(curl -s "${insecure[@]}" -o /dev/null -w '%{http_code}' --max-time 60 \
            --resolve "$domain:$port:127.0.0.1" "$url" || true)
    else
        host="${LISTEN%:*}"
        [[ -z "$host" || "$host" == "0.0.0.0" || "$host" == "[::]" ]] && host=127.0.0.1
        url="http://$host:$port/"
        code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$url" || true)
    fi

    if [[ -n "$code" && "$code" != "000" ]]; then
        ok "$url answered $code"
    else
        warn "nothing answered at $url"
        [[ -n "$domain" ]] && echo "  Check: journalctl -u concert -n 50 --no-pager | grep -iE 'tls|acme'" >&2
    fi

    report_avcs || true
}

# ── Install ──────────────────────────────────────────────────────────

do_install() {
    WORK=$(mktemp -d)

    if selinux_active; then
        log "SELinux is $(getenforce)"
        [[ "$(getenforce)" == "Enforcing" ]] || warn "SELinux is not enforcing; the policy is installed anyway"
        ensure_selinux_tooling
    else
        warn "SELinux is disabled; installing without a policy module"
    fi

    resolve_binary
    ensure_user
    write_env_file

    for p in "$(port_of_addr "$LISTEN")" "$(port_of_url "$UPSTREAM")" "$(port_of_addr "$PORTAL_LISTEN")"; do
        valid_port "$p" || die "invalid port '$p' in $ENV_FILE or $DATA_DIR/settings.json"
    done

    if selinux_active; then
        load_policy
        label_port "$(port_of_addr "$LISTEN")"        concert_port_t          http_port_t http_cache_port_t
        label_port "$(port_of_addr "$PORTAL_LISTEN")" concert_port_t          http_port_t http_cache_port_t
        label_port "$(port_of_url "$UPSTREAM")"       concert_upstream_port_t http_port_t http_cache_port_t
    fi

    ensure_state_dir
    install_binary
    preflight_exec
    write_unit
    open_firewall

    systemctl enable --quiet concert
    systemctl restart concert
    verify

    echo
    echo "${BOLD}concert is installed.${RESET}"
    echo "  binary:   $BIN  (from $BINARY_SRC)"
    echo "  listen:   $LISTEN  ->  $UPSTREAM"
    echo "  portal:   $PORTAL_LISTEN"
    echo "  config:   $ENV_FILE"
    echo "  data:     $DATA_DIR  (settings.json, bans.json)"
    echo "  state:    $STATE_DIR"
    echo "  logs:     journalctl -u concert -f"
    if (( FIRST_INSTALL )); then
        echo
        echo "  Portal password (shown once, stored in $ENV_FILE):"
        echo "    ${BOLD}$PORTAL_PASS${RESET}"
    fi
}

# ── Uninstall ────────────────────────────────────────────────────────

do_uninstall() {
    log "Stopping concert"
    systemctl disable --now concert 2>/dev/null || true
    rm -f -- "$UNIT"
    systemctl daemon-reload

    if [[ -f "$STATE" ]]; then
        while read -r kind port; do
            case "$kind" in
                port)
                    selinux_active && semanage port -d -p tcp "$port" 2>/dev/null \
                        && ok "Removed label on tcp/$port" ;;
                fw)
                    systemctl is-active --quiet firewalld \
                        && firewall-cmd --quiet --permanent --remove-port="$port/tcp" \
                        && firewall-cmd --quiet --reload \
                        && ok "Closed tcp/$port in firewalld" ;;
            esac
        done < "$STATE"
        rm -f -- "$STATE"
    fi

    # Port labels must go before the module, or semodule refuses to remove it.
    if selinux_active && semodule -l | grep -qE "^${MODULE}([[:space:]]|$)"; then
        semodule -r "$MODULE" && ok "Removed SELinux module $MODULE"
    fi

    rm -f -- "$BIN"
    ok "Removed $BIN"

    if [[ "$PURGE" == "1" ]]; then
        rm -rf -- "$ETC" "$STATE_DIR"
        getent passwd "$SVC_USER" >/dev/null && userdel "$SVC_USER"
        ok "Purged $ETC, $STATE_DIR (including settings and bans) and user $SVC_USER"
    else
        echo "  Kept $ETC, $STATE_DIR (settings and bans) and user $SVC_USER (PURGE=1 removes them)"
    fi
}

# ── Main ─────────────────────────────────────────────────────────────

case "${1:-install}" in
    install)   do_install ;;
    uninstall) do_uninstall ;;
    *)         die "usage: $0 [install|uninstall]" ;;
esac
