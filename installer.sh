#!/usr/bin/env bash
#
# installer.sh — install a prebuilt concert binary as a confined systemd
# service that runs under SELinux enforcing mode, with the IPtoASN database
# the admin portal uses for IP details.
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
#   sudo FORCE_RESTART=1 bash installer.sh                   # restart even if nothing changed
#   sudo bash installer.sh uninstall                         # remove service, policy, port labels, timer
#   sudo PURGE=1 bash installer.sh uninstall                 # also remove /etc/concert, /var/lib/concert, the user
#
# Settings (first install only; afterwards edit /etc/concert/concert.env, or
# change them live in the admin portal):
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
# IP details in the admin portal (naddr's ess package). concert reads
# NADDR_DATA, an IPtoASN file, or NADDR_ADDR, a running naddr service; with
# neither, the portal shows bare addresses. By default the installer
# downloads the database to /var/lib/concert/naddr/ip2asn-combined.tsv.gz,
# labels it for concert under SELinux, and installs a daily timer
# (concert-naddr-data.timer) that refreshes it atomically. concert reloads a
# replaced file on its own (NADDR_DATA_POLL); no restart is needed.
#
#   NADDR_DATA=/srv/naddr/ip2asn.tsv.gz   keep the database here instead (labeled for concert)
#   NADDR_ADDR=127.0.0.1:8080             use a naddr service (its port is labeled for concert)
#   NADDR_DOWNLOAD=0                      don't download or schedule refreshes
#   NADDR_REFRESH=1                       download the database again now
#
# Existing installs get NADDR_DATA, NADDR_DATA_POLL and NADDR_ADDR added to
# concert.env when missing; NADDR_DATA or NADDR_ADDR given to this run
# replace the values there.
#
# Wallet access: x402 passes and NFT holders (docs/FASTLANE.md). concert reads
# /etc/concert/fastlane.json (offers and NFT rules) and
# /etc/concert/networks.json (chain endpoints); the chain gateway runs inside
# concert. Under SELinux enforcing both files must be concert_etc_t. A file
# written in a home directory and moved into /etc/concert keeps user_home_t,
# concert is denied reading it, and it fails to start. Hand the files to the
# installer instead: it installs root-owned copies readable by concert,
# applies the label, checks it, and sets CONCERT_FASTLANE_CONFIG and
# CONCERT_NETWORKS_CONFIG in concert.env.
#
#   sudo CONCERT_FASTLANE_CONFIG=/home/rocky/fastlane.json \
#        CONCERT_NETWORKS_CONFIG=/home/rocky/networks.json \
#        bash installer.sh
#
# Start from the samples every run writes beside them,
# /etc/concert/fastlane.example.json and networks.example.json (also printed
# by "concert example fastlane|networks"); docs/FASTLANE.md explains every
# key. Files already in /etc/concert are relabeled and checked on every run,
# so after editing one in place, re-run the installer: it restarts concert
# because the file changed. A path in concert.env outside /etc/concert is
# copied in the same way. The chain endpoint ports networks.json names (XRPL
# JSON-RPC is 51234), 50211 for Hedera consensus nodes, and the policy_url
# port are labeled so concert may connect to them. Sponsor keys go in
# concert.env: CONCERT_STELLAR_FEE_SECRET and CONCERT_HEDERA_FEE_SECRET. The
# settlement journal lives in /var/lib/concert/data/gateway.
#
#   CONCERT_FASTLANE_CONFIG=/path     install this file as /etc/concert/fastlane.json
#   CONCERT_NETWORKS_CONFIG=/path     install this file as /etc/concert/networks.json
#
# Ports concert may move to while running. Every setting, including the
# listen and portal addresses, can be changed live in the admin portal. A new
# port must be one SELinux lets concert bind, and one below 1024 needs
# CAP_NET_BIND_SERVICE. These are remembered in /etc/concert/installer.env:
#
#   CONCERT_EXTRA_PORTS=9090,8443     label these ports for concert now
#   ALLOW_LOW_PORTS=1                 always grant CAP_NET_BIND_SERVICE
#   SELINUX_ANY_PORT=1                turn on the concert_bind_any_port boolean:
#                                     concert may bind any unreserved port
#                                     (0 turns it off; toggle later with
#                                     setsebool -P concert_bind_any_port on|off)
#
# Other knobs:
#   CONCERT_BINARY=/path/to/concert   binary to install (default: /home/rocky/concert-linux-amd64,
#                                     then the installed copy)
#   CONCERT_SHA256=<sum>              refuse to install a binary with a different checksum
#   CONCERT_PORTAL_LISTEN / CONCERT_PORTAL_ALLOW   admin portal address and CIDRs
#   INSTALL_DEPS=0                    don't dnf-install missing SELinux tooling
#   FORCE_RESTART=1                   restart even when nothing that needs it changed
#
# What it does:
#   1. verifies the binary and installs a root-owned copy
#   2. compiles and loads an SELinux module that confines concert in concert_t
#   3. labels the listen, portal, upstream, naddr and extra ports
#   4. creates /var/lib/concert for the Let's Encrypt certificate cache and
#      /var/lib/concert/data for settings.json, bans.json, the saved queue
#      and the history log (history.jsonl)
#   5. downloads the IPtoASN database, labels it concert_var_lib_t, and
#      installs the daily refresh timer
#   6. writes /etc/concert/concert.env (secrets generated once, kept on upgrade)
#   7. installs fastlane.json and networks.json as concert_etc_t, labels the
#      chain endpoint ports they name, and writes the sample configuration
#   8. installs a hardened systemd unit and (re)starts concert only when
#      something that needs a restart changed, then verifies the process is
#      running in concert_t with no AVC denials
#
# A restart keeps the waiting queue (saved on shutdown), bans, settings
# changed in the portal and the request history, all in /var/lib/concert/data.
# The installer still restarts concert only for a new binary, a changed unit,
# a changed concert.env, fastlane.json or networks.json, a stopped service, or
# FORCE_RESTART=1. On stop, concert lets payment settlements in flight record
# their results first.
#
# concert reads every setting from CONCERT_* environment variables, so the
# unit passes no flags: /etc/concert/concert.env is the configuration, except
# for values changed in the admin portal, which concert saves to
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
INSTALLER_ENV="$ETC/installer.env"
ENV_SUM="$ETC/.installer-envsum"
STATE="$ETC/.installer-state"
STATE_DIR=/var/lib/concert
DATA_DIR="$STATE_DIR/data"
UNIT=/etc/systemd/system/concert.service
SVC_USER=concert
MODULE=concert
SEBOOL=concert_bind_any_port
DEVEL_MAKEFILE=/usr/share/selinux/devel/Makefile

NADDR_URL=https://iptoasn.com/data/ip2asn-combined.tsv.gz
NADDR_DEFAULT_FILE="$STATE_DIR/naddr/ip2asn-combined.tsv.gz"
NADDR_UPDATER=/usr/local/libexec/concert-naddr-update
NADDR_SERVICE=/etc/systemd/system/concert-naddr-data.service
NADDR_TIMER=/etc/systemd/system/concert-naddr-data.timer

FASTLANE_FILE="$ETC/fastlane.json"
NETWORKS_FILE="$ETC/networks.json"

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
FORCE_RESTART="${FORCE_RESTART:-0}"
PURGE="${PURGE:-0}"

NADDR_DATA_WANT="${NADDR_DATA-}"
NADDR_DATA_GIVEN="${NADDR_DATA+1}"
NADDR_ADDR_WANT="${NADDR_ADDR-}"
NADDR_ADDR_GIVEN="${NADDR_ADDR+1}"
NADDR_DOWNLOAD="${NADDR_DOWNLOAD:-1}"
NADDR_REFRESH="${NADDR_REFRESH:-0}"

FASTLANE_SRC="${CONCERT_FASTLANE_CONFIG:-}"
NETWORKS_SRC="${CONCERT_NETWORKS_CONFIG:-}"

# Remembered in $INSTALLER_ENV. "given" records whether this run set them,
# so a plain re-run keeps what an earlier run chose.
EXTRA_PORTS="${CONCERT_EXTRA_PORTS-}"
EXTRA_PORTS_GIVEN="${CONCERT_EXTRA_PORTS+1}"
LOW_PORTS="${ALLOW_LOW_PORTS-}"
LOW_PORTS_GIVEN="${ALLOW_LOW_PORTS+1}"
ANY_PORT="${SELINUX_ANY_PORT-}"

# Read from concert.env once it exists.
NADDR_PATH=""
NADDR_REMOTE=""

# Set by install_fastlane: off, disabled (file present, "enabled": false) or on.
FASTLANE_STATE="off"

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

# NADDR_ADDR may be host:port or a URL.
naddr_url() { [[ "$1" == *://* ]] && echo "$1" || echo "http://$1"; }

valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )); }

# Read KEY=value from the env file without sourcing it. EnvironmentFile has
# no trailing-comment syntax, so the value is everything after the "=".
env_get() { sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1; }

# env_set KEY VALUE — replace KEY's line in the env file, or append it.
env_set() {
    local key=$1 val=$2 tmp
    if grep -q "^$key=" "$ENV_FILE"; then
        [[ "$(env_get "$key")" == "$val" ]] && return 0
        tmp=$(mktemp "$ETC/.concert.env.XXXXXX")
        awk -v k="$key" -v v="$val" 'index($0, k "=") == 1 { print k "=" v; next } { print }' "$ENV_FILE" > "$tmp"
        cat "$tmp" > "$ENV_FILE"
        rm -f -- "$tmp"
    else
        printf '%s=%s\n' "$key" "$val" >> "$ENV_FILE"
    fi
    ok "Set $key in $ENV_FILE"
}

state_add() {
    touch "$STATE" && chmod 600 "$STATE"
    grep -qxF "$1" "$STATE" || echo "$1" >> "$STATE"
}

# ── Restart tracking ─────────────────────────────────────────────────

# Reasons collected while installing; concert restarts only if there are any.
RESTART_REASONS=()
need_restart() { RESTART_REASONS+=("$1"); }

# ── Binary ───────────────────────────────────────────────────────────

BINARY_SUM=""

# Source binary, in order: CONCERT_BINARY, the pipeline's upload at
# $DEFAULT_BINARY, or the copy already at $BIN (reinstalled in place with
# correct ownership and label).
resolve_binary() {
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

    BINARY_SUM=$(sha256sum "$BINARY_SRC" | awk '{print $1}')
    if [[ -n "$BINARY_SHA256" && "$BINARY_SUM" != "$BINARY_SHA256" ]]; then
        die "sha256 mismatch for $BINARY_SRC: got $BINARY_SUM, expected $BINARY_SHA256"
    fi
    ok "Using $BINARY_SRC (sha256 $BINARY_SUM)"
}

install_binary() {
    # A fresh root-owned 0755 copy whenever the binary changed. The uploaded
    # file's owner, mode and SELinux label come from whoever uploaded it, so
    # it is never used as-is. restorecon is what applies concert_exec_t; a
    # plain mv would keep the label the file was created with.
    local installed=""
    [[ -f "$BIN" ]] && installed=$(sha256sum "$BIN" | awk '{print $1}')

    if [[ "$installed" == "$BINARY_SUM" ]]; then
        ok "$BIN is already this build"
    else
        install -m 0755 -o root -g root "$BINARY_SRC" "$BIN.new"
        mv -f -- "$BIN.new" "$BIN"
        need_restart "new binary"
    fi

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
policy_module(concert, 1.2.0)

########################################
# Declarations

## <desc>
## <p>
## Allow concert to listen on any unreserved port, so its listen and portal
## addresses can move to ports that were not labeled at install time.
## </p>
## </desc>
gen_tunable(concert_bind_any_port, false)

type concert_t;
type concert_exec_t;
init_daemon_domain(concert_t, concert_exec_t)

type concert_etc_t;
files_config_file(concert_etc_t)

# Let's Encrypt account key and certificates, settings.json, bans.json, the
# saved queue, the history log and the IPtoASN database under
# /var/lib/concert (and any NADDR_DATA directory the installer labels).
type concert_var_lib_t;
files_type(concert_var_lib_t)

# Ports concert may listen on (main listener, admin portal, extra ports).
type concert_port_t;
corenet_port(concert_port_t)

# Ports concert may connect to: its upstream origin, a naddr service, chain
# endpoints outside the web ports, and a policy service.
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

# Configuration under /etc/concert, including fastlane.json and networks.json
list_dirs_pattern(concert_t, concert_etc_t, concert_etc_t)
read_files_pattern(concert_t, concert_etc_t, concert_etc_t)

# State under /var/lib/concert
files_search_var_lib(concert_t)
manage_dirs_pattern(concert_t, concert_var_lib_t, concert_var_lib_t)
manage_files_pattern(concert_t, concert_var_lib_t, concert_var_lib_t)

# Listening: its own ports, plus the standard web ports (80/443, 8080, ...)
corenet_tcp_bind_generic_node(concert_t)
allow concert_t { concert_port_t http_port_t http_cache_port_t }:tcp_socket name_bind;

# Listen addresses changed in the admin portal, on ports nobody labeled.
tunable_policy(`concert_bind_any_port',`
	corenet_tcp_bind_all_unreserved_ports(concert_t)
')

# Upstream origin, a naddr service, chain endpoints, a policy service, and
# HTTPS on 443 (http_port_t): Let's Encrypt and chain RPC
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
    ok "Loaded SELinux module ${BOLD}$MODULE${RESET} (no restart needed)"
}

# Applies SELINUX_ANY_PORT when this run set it; otherwise leaves the boolean
# as it is, so a setsebool made by hand survives re-runs.
apply_selinux_boolean() {
    case "$ANY_PORT" in
        1) setsebool -P "$SEBOOL" on  && ok "SELinux boolean $SEBOOL is on: concert may bind any unreserved port" ;;
        0) setsebool -P "$SEBOOL" off && ok "SELinux boolean $SEBOOL is off" ;;
        "") ;;
        *) die "SELINUX_ANY_PORT must be 0 or 1" ;;
    esac
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

# ── Installer choices ────────────────────────────────────────────────

# Loads CONCERT_EXTRA_PORTS and ALLOW_LOW_PORTS from $INSTALLER_ENV unless
# this run set them, validates them, and saves them back.
load_installer_settings() {
    local saved_extra="" saved_low="" p
    if [[ -f "$INSTALLER_ENV" ]]; then
        saved_extra=$(sed -n 's/^EXTRA_PORTS=//p' "$INSTALLER_ENV" | tail -n 1)
        saved_low=$(sed -n 's/^ALLOW_LOW_PORTS=//p' "$INSTALLER_ENV" | tail -n 1)
    fi
    [[ -n "$EXTRA_PORTS_GIVEN" ]] || EXTRA_PORTS="$saved_extra"
    [[ -n "$LOW_PORTS_GIVEN" ]]   || LOW_PORTS="$saved_low"

    EXTRA_PORTS="${EXTRA_PORTS// /}"
    LOW_PORTS="${LOW_PORTS:-0}"
    [[ "$LOW_PORTS" == "0" || "$LOW_PORTS" == "1" ]] || die "ALLOW_LOW_PORTS must be 0 or 1"
    for p in ${EXTRA_PORTS//,/ }; do
        valid_port "$p" || die "invalid port '$p' in CONCERT_EXTRA_PORTS"
    done

    ( umask 077
      cat > "$INSTALLER_ENV" <<EOF
# Choices made by installer.sh, kept for later runs. Not read by concert.
EXTRA_PORTS=$EXTRA_PORTS
ALLOW_LOW_PORTS=$LOW_PORTS
EOF
    )
    chown root:root "$INSTALLER_ENV"
    selinux_active && restorecon -F "$INSTALLER_ENV"
    return 0
}

# Every port concert is configured or allowed to listen on.
listen_ports() {
    local p
    for p in "$(port_of_addr "$LISTEN")" "$(port_of_addr "$PORTAL_LISTEN")" ${EXTRA_PORTS//,/ }; do
        [[ -n "$p" ]] && echo "$p"
    done | sort -un
}

needs_low_port_cap() {
    [[ "$LOW_PORTS" == "1" ]] && return 0
    local p
    for p in $(listen_ports); do
        (( p < 1024 )) && return 0
    done
    return 1
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
# /var/lib/concert/data holds settings.json, bans.json, the saved queue and
# the history log. The unit's StateDirectory= also creates /var/lib/concert
# and bind-mounts it writable past ProtectSystem=strict; doing it here as
# well lets restorecon label both before the first start. Existing data is
# never touched. Must run after load_policy, when the type exists.
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
    for f in settings.json bans.json queue.snapshot history.jsonl; do
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

# The NADDR_DATA a new install or a migrated env file gets.
naddr_default_data() {
    if [[ -n "$NADDR_DATA_WANT" ]]; then
        echo "$NADDR_DATA_WANT"
    elif [[ "$NADDR_DOWNLOAD" == "1" ]]; then
        echo "$NADDR_DEFAULT_FILE"
    fi
}

naddr_env_block() {
    cat <<EOF

# IP details in the admin portal (naddr's ess package). NADDR_DATA names an
# IPtoASN file (plain or .gz); NADDR_ADDR a running naddr service, used when
# NADDR_DATA is empty or cannot be loaded. Leave both empty to turn IP
# details off. concert reloads a replaced NADDR_DATA file every NADDR_DATA_POLL.
NADDR_DATA=$(naddr_default_data)
NADDR_DATA_POLL=5m
NADDR_ADDR=$NADDR_ADDR_WANT
EOF
}

fastlane_env_block() {
    cat <<EOF

# Wallet access (docs/FASTLANE.md). installer.sh sets the two paths when it
# installs fastlane.json and networks.json; empty turns wallet access off.
# Sponsor keys pay Stellar and Hedera network fees for payers: use dedicated
# low-balance accounts. CONCERT_POLICY_TOKEN authenticates to policy_url.
CONCERT_FASTLANE_CONFIG=
CONCERT_NETWORKS_CONFIG=
CONCERT_POLICY_TOKEN=
CONCERT_STELLAR_FEE_SECRET=
CONCERT_HEDERA_FEE_SECRET=
EOF
}

# Existing env files from before IP details get the NADDR_* block; values
# given to this run replace what is there.
ensure_naddr_env() {
    if ! grep -qE '^NADDR_(DATA|ADDR)=' "$ENV_FILE"; then
        naddr_env_block >> "$ENV_FILE"
        ok "Added NADDR_DATA, NADDR_DATA_POLL and NADDR_ADDR to $ENV_FILE"
        return 0
    fi
    [[ -n "$NADDR_DATA_GIVEN" ]] && env_set NADDR_DATA "$NADDR_DATA_WANT"
    [[ -n "$NADDR_ADDR_GIVEN" ]] && env_set NADDR_ADDR "$NADDR_ADDR_WANT"
    return 0
}

write_env_file() {
    install -d -m 0750 -o root -g "$SVC_USER" "$ETC"

    if [[ -f "$ENV_FILE" ]]; then
        migrate_env_file
        check_env_file
        ensure_naddr_env
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
# Values changed in the admin portal apply immediately, are saved to
# $DATA_DIR/settings.json, and take priority over this file;
# use Reset in the portal to hand a setting back to this file.
# After editing this file, re-run installer.sh (it restarts concert because
# the file changed), or at least:
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

# Portal settings, bans, the saved queue and the history log
# (settings.json, bans.json, queue.snapshot, history.jsonl).
CONCERT_DATA_DIR=$DATA_DIR

# Let's Encrypt. A non-empty CONCERT_TLS_DOMAINS serves CONCERT_LISTEN over TLS.
CONCERT_TLS_DOMAINS=$TLS_DOMAINS
CONCERT_TLS_EMAIL=$TLS_EMAIL
CONCERT_TLS_CACHE=$STATE_DIR/acme
CONCERT_TLS_STAGING=$TLS_STAGING

CONCERT_ADMIT_SECRET=$secret
CONCERT_PORTAL_PASS=$PORTAL_PASS
EOF
          naddr_env_block >> "$ENV_FILE"
          fastlane_env_block >> "$ENV_FILE"
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
    NADDR_PATH=$(env_get NADDR_DATA)
    NADDR_REMOTE=$(env_get NADDR_ADDR)

    # Ports changed in the portal live in settings.json and win over the env
    # file, so the port labels must follow them.
    settings_override upstream      UPSTREAM

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

# concert.env, fastlane.json and networks.json only take effect on a
# restart; compare them with what concert was last (re)started with. Without
# the fast lane files this is the checksum of concert.env alone, as before.
config_sum() {
    local files=("$ENV_FILE") f
    for f in "$FASTLANE_FILE" "$NETWORKS_FILE"; do
        [[ -f "$f" ]] && files+=("$f")
    done
    cat -- "${files[@]}" | sha256sum | awk '{print $1}'
}

env_changed() {
    [[ -f "$ENV_SUM" ]] || return 0
    [[ "$(config_sum)" != "$(cat "$ENV_SUM")" ]]
}

record_env() {
    ( umask 077; config_sum > "$ENV_SUM" )
}

# ── IPtoASN database (NADDR_DATA) ────────────────────────────────────

# The refresh script: download to a temporary file beside the target,
# verify it, give it to root:concert 0640 and move it into place atomically,
# so concert never reads a partial file. restorecon keeps its label.
write_naddr_updater() {
    local new="$WORK/concert-naddr-update"
    {
        echo '#!/usr/bin/env bash'
        echo '# concert-naddr-update — refresh the IPtoASN database concert reads (NADDR_DATA).'
        echo '# Written by installer.sh; run daily by concert-naddr-data.timer.'
        echo 'set -euo pipefail'
        printf 'target=%q\nurl=%q\ngroup=%q\n' "$NADDR_PATH" "$NADDR_URL" "$SVC_USER"
        cat <<'EOF'
dir=$(dirname "$target")
tmp=$(mktemp "$dir/.ip2asn.XXXXXX")
trap 'rm -f -- "$tmp"' EXIT
curl -fsSL --retry 3 --max-time 600 -o "$tmp" "$url"
gzip -t "$tmp"
chown root:"$group" "$tmp"
chmod 0640 "$tmp"
mv -f -- "$tmp" "$target"
trap - EXIT
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F "$target" || true
fi
echo "concert-naddr-update: refreshed $target"
EOF
    } > "$new"
    install -d -m 0755 -o root -g root "$(dirname "$NADDR_UPDATER")"
    install -m 0755 -o root -g root "$new" "$NADDR_UPDATER"
    selinux_active && restorecon -F "$NADDR_UPDATER"
    return 0
}

install_naddr_timer() {
    local svc="$WORK/concert-naddr-data.service" tmr="$WORK/concert-naddr-data.timer" changed=0
    cat > "$svc" <<EOF
[Unit]
Description=Refresh the IPtoASN database concert uses for IP details (NADDR_DATA)
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=$NADDR_UPDATER
EOF
    cat > "$tmr" <<'EOF'
[Unit]
Description=Daily refresh of the IPtoASN database for concert

[Timer]
OnCalendar=daily
RandomizedDelaySec=2h
Persistent=true

[Install]
WantedBy=timers.target
EOF
    if ! cmp -s "$svc" "$NADDR_SERVICE"; then install -m 0644 -o root -g root "$svc" "$NADDR_SERVICE"; changed=1; fi
    if ! cmp -s "$tmr" "$NADDR_TIMER"; then install -m 0644 -o root -g root "$tmr" "$NADDR_TIMER"; changed=1; fi
    if (( changed )); then
        selinux_active && restorecon -F "$NADDR_SERVICE" "$NADDR_TIMER"
        systemctl daemon-reload
    fi
    systemctl enable --now --quiet concert-naddr-data.timer
    ok "concert-naddr-data.timer refreshes $NADDR_PATH daily"
}

# Puts the IPtoASN database where NADDR_DATA says, labels it so concert_t
# can read it, and schedules its refresh. A failed download never stops the
# install: concert starts without IP details and loads the file as soon as
# it appears (it retries every minute).
install_naddr_data() {
    if [[ -z "$NADDR_PATH" ]]; then
        if [[ -n "$NADDR_REMOTE" ]]; then
            ok "IP details from the naddr service at $NADDR_REMOTE"
        else
            warn "NADDR_DATA and NADDR_ADDR are empty in $ENV_FILE: the portal shows bare addresses"
        fi
        return 0
    fi
    [[ "$NADDR_PATH" == /* ]] || die "NADDR_DATA must be an absolute path: $NADDR_PATH"
    case "$NADDR_PATH" in
        /home/*|/root/*|/tmp/*|/var/tmp/*|/run/user/*)
            die "NADDR_DATA=$NADDR_PATH is hidden from concert by ProtectHome=/PrivateTmp=; keep it under $STATE_DIR or /srv" ;;
    esac

    local dir
    dir=$(dirname "$NADDR_PATH")

    # Directories outside /var/lib/concert get their own file-context rule,
    # so restorecon (and the refresh script) give them concert_var_lib_t.
    if selinux_active && [[ "$dir" != "$STATE_DIR" && "$dir" != "$STATE_DIR"/* ]]; then
        local spec="$dir(/.*)?"
        if semanage fcontext -l | awk '{print $1}' | grep -qxF "$spec"; then
            semanage fcontext -m -t concert_var_lib_t "$spec"
        else
            semanage fcontext -a -t concert_var_lib_t "$spec"
        fi
        state_add "fcontext $spec"
        ok "File context $spec is concert_var_lib_t"
    fi

    install -d -m 0750 -o root -g "$SVC_USER" "$dir"
    selinux_active && restorecon -RF "$dir"

    if [[ "$NADDR_DOWNLOAD" == "1" ]]; then
        write_naddr_updater
        if [[ ! -s "$NADDR_PATH" || "$NADDR_REFRESH" == "1" ]]; then
            log "Downloading the IPtoASN database to $NADDR_PATH"
            if "$NADDR_UPDATER" >/dev/null; then
                ok "Downloaded $NADDR_PATH ($(du -h "$NADDR_PATH" | awk '{print $1}'))"
            else
                warn "downloading $NADDR_URL failed; concert starts without IP details and loads $NADDR_PATH once it exists"
                echo "  Retry now: $NADDR_UPDATER   (the daily timer retries on its own)" >&2
            fi
        else
            ok "Keeping existing $NADDR_PATH (NADDR_REFRESH=1 downloads it again)"
        fi
        install_naddr_timer
    elif [[ ! -s "$NADDR_PATH" ]]; then
        warn "NADDR_DOWNLOAD=0 and $NADDR_PATH does not exist: supply it, and concert loads it within a minute"
    fi

    if [[ -f "$NADDR_PATH" ]]; then
        chown root:"$SVC_USER" "$NADDR_PATH"
        chmod 0640 "$NADDR_PATH"
        if selinux_active; then
            restorecon -F "$NADDR_PATH"
            [[ "$(stat -c %C "$NADDR_PATH")" == *concert_var_lib_t* ]] \
                || die "$NADDR_PATH is $(stat -c %C "$NADDR_PATH"), expected concert_var_lib_t"
            ok "$NADDR_PATH ($(stat -c %C "$NADDR_PATH"))"
        fi
        runuser -u "$SVC_USER" -- test -r "$NADDR_PATH" \
            || die "user $SVC_USER cannot read $NADDR_PATH (check the modes of $dir and its parents)"
    fi
    return 0
}

# ── Wallet access (fast lane) ────────────────────────────────────────

# install_config SRC DEST — install DEST as a root:concert 0640 file that
# SELinux labels concert_etc_t. A SRC outside /etc/concert is copied in fresh:
# its owner, mode and label (user_home_t for a file from a home directory)
# come from whoever wrote it, and mv would keep that label, so it is never
# moved into place. An existing DEST is re-owned and relabeled on every run.
install_config() {
    local src=$1 dest=$2
    if [[ -n "$src" && "$src" != "$dest" ]]; then
        [[ -f "$src" && -r "$src" ]] || die "$src is not a readable file"
        json_check "$src"
        if [[ -f "$dest" ]] && cmp -s "$src" "$dest"; then
            ok "$dest is already a copy of $src"
        else
            install -m 0640 -o root -g "$SVC_USER" "$src" "$dest.new"
            mv -f -- "$dest.new" "$dest"
            ok "Installed $src as $dest"
        fi
    fi
    [[ -f "$dest" ]] || return 0
    json_check "$dest"
    chown root:"$SVC_USER" "$dest"
    chmod 0640 "$dest"
    if selinux_active; then
        restorecon -F "$dest"
        [[ "$(stat -c %C "$dest")" == *concert_etc_t* ]] \
            || die "$dest is $(stat -c %C "$dest"), expected concert_etc_t"
        ok "$dest ($(stat -c %C "$dest"))"
    fi
    runuser -u "$SVC_USER" -- test -r "$dest" \
        || die "user $SVC_USER cannot read $dest (check the modes of $ETC)"
}

# json_check FILE — refuse a file that is not a JSON object, when a Python
# interpreter is available to tell (RHEL ships /usr/libexec/platform-python).
PY=""
json_check() {
    if [[ -z "$PY" ]]; then
        PY=$(command -v python3 || true)
        [[ -z "$PY" && -x /usr/libexec/platform-python ]] && PY=/usr/libexec/platform-python
        [[ -n "$PY" ]] || PY=none
    fi
    [[ "$PY" == none ]] && return 0
    "$PY" -c 'import json, sys; d = json.load(open(sys.argv[1])); sys.exit(0 if isinstance(d, dict) else 1)' "$1" 2>/dev/null \
        || die "$1 is not a valid JSON object (compare it with 'concert example fastlane' or 'concert example networks')"
}

# fastlane_path VAR FILE SRC_VAR — which file concert.env's VAR names. A path
# outside /etc/concert becomes the source to copy in, unless this run gave one.
fastlane_path() {
    local var=$1 file=$2 srcvar=$3 cur
    cur=$(env_get "$var")
    if [[ -n "$cur" && "$cur" != "$file" && -z "${!srcvar}" ]]; then
        warn "$ENV_FILE names $cur for $var; installing it as $file, which concert reads from now on"
        printf -v "$srcvar" '%s' "$cur"
    fi
}

# Installs fastlane.json and networks.json with the label concert needs and
# points concert.env at them. Must run after load_policy, when concert_etc_t
# exists.
install_fastlane() {
    grep -q '^CONCERT_FASTLANE_CONFIG=' "$ENV_FILE" || { fastlane_env_block >> "$ENV_FILE"; ok "Added the wallet access settings to $ENV_FILE"; }
    fastlane_path CONCERT_FASTLANE_CONFIG "$FASTLANE_FILE" FASTLANE_SRC
    fastlane_path CONCERT_NETWORKS_CONFIG "$NETWORKS_FILE" NETWORKS_SRC
    install_config "$FASTLANE_SRC" "$FASTLANE_FILE"
    install_config "$NETWORKS_SRC" "$NETWORKS_FILE"

    if [[ ! -f "$FASTLANE_FILE" ]]; then
        [[ -z "$(env_get CONCERT_FASTLANE_CONFIG)" ]] \
            || die "$ENV_FILE names $FASTLANE_FILE, which does not exist: supply it with CONCERT_FASTLANE_CONFIG=/path, or empty CONCERT_FASTLANE_CONFIG"
        ok "Wallet access is off (no $FASTLANE_FILE; start from $ETC/fastlane.example.json)"
        return 0
    fi
    env_set CONCERT_FASTLANE_CONFIG "$FASTLANE_FILE"
    FASTLANE_STATE=disabled
    grep -qE '"enabled"[[:space:]]*:[[:space:]]*true' "$FASTLANE_FILE" && FASTLANE_STATE=on

    if [[ -f "$NETWORKS_FILE" ]]; then
        env_set CONCERT_NETWORKS_CONFIG "$NETWORKS_FILE"
    elif [[ "$FASTLANE_STATE" == on ]]; then
        die "$FASTLANE_FILE is enabled but $NETWORKS_FILE does not exist: supply it with CONCERT_NETWORKS_CONFIG=/path (start from $ETC/networks.example.json)"
    fi
    if [[ "$FASTLANE_STATE" == on ]]; then
        ok "Wallet access is on"
    else
        ok "Wallet access is configured but \"enabled\" is false in $FASTLANE_FILE"
    fi
}

# Ports concert connects to for wallet access: chain endpoints networks.json
# names, Hedera consensus nodes (plaintext gRPC on 50211) and policy_url.
# HTTPS on 443 is already permitted (http_port_t).
fastlane_ports() {
    [[ "$FASTLANE_STATE" == on ]] || return 0
    local url
    {
        [[ -f "$NETWORKS_FILE" ]] && grep -oE 'https?://[^"]+' "$NETWORKS_FILE" || true
        grep -oE '"policy_url"[[:space:]]*:[[:space:]]*"[^"]+"' "$FASTLANE_FILE" | grep -oE 'https?://[^"]+' || true
    } | while read -r url; do
        port_of_url "$url"
    done
    grep -q '"hedera:' "$FASTLANE_FILE" && echo 50211
    return 0
}

label_fastlane_ports() {
    local p
    for p in $(fastlane_ports | sort -un); do
        valid_port "$p" || die "invalid port $p in $NETWORKS_FILE or policy_url"
        label_port "$p" concert_upstream_port_t http_port_t http_cache_port_t
    done
}

# Reference copies of the sample configuration from the installed binary,
# refreshed every run. concert never reads them.
write_examples() {
    local kind dest
    for kind in fastlane networks; do
        dest="$ETC/$kind.example.json"
        if "$BIN" example "$kind" > "$WORK/$kind.example.json" 2>/dev/null; then
            install -m 0640 -o root -g "$SVC_USER" "$WORK/$kind.example.json" "$dest"
            selinux_active && restorecon -F "$dest"
        else
            warn "$BIN cannot print the $kind example (an older build?); see docs/FASTLANE.md"
            return 0
        fi
    done
    ok "Sample configuration: $ETC/fastlane.example.json, $ETC/networks.example.json (docs/FASTLANE.md explains every key)"
}

# ── systemd unit ─────────────────────────────────────────────────────

write_unit() {
    local caps="" new="$WORK/concert.service"
    if needs_low_port_cap; then
        caps="CAP_NET_BIND_SERVICE"
    fi

    cat > "$new" <<EOF
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
# On stop, payment settlements in flight record their results before concert
# exits (each is bounded by its offer's maxTimeoutSeconds plus 3 minutes).
TimeoutStopSec=10min

# Certificate cache, settings.json, bans.json, the saved queue, the history
# log and the IPtoASN database. ProtectSystem=strict makes the filesystem
# read-only; StateDirectory= is the writable carve-out.
StateDirectory=concert
StateDirectoryMode=0700

# Hardening. CAP_NET_BIND_SERVICE is granted only when a listen, portal or
# extra port is below 1024, or ALLOW_LOW_PORTS=1.
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

    if [[ -f "$UNIT" ]] && cmp -s "$new" "$UNIT"; then
        ok "$UNIT unchanged"
        return
    fi
    install -m 0644 -o root -g root "$new" "$UNIT"
    selinux_active && restorecon -F "$UNIT"
    systemctl daemon-reload
    need_restart "unit changed"
    ok "Installed $UNIT${caps:+ (with $caps)}"
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

# ── Service ──────────────────────────────────────────────────────────

RESTARTED=0

# Starts concert, or restarts it when something that only takes effect at
# startup changed. Otherwise it keeps running.
apply_service() {
    systemctl enable --quiet concert

    if ! systemctl is-active --quiet concert; then
        log "Starting concert"
        systemctl start concert
        RESTARTED=1
    else
        env_changed && need_restart "$ENV_FILE or the fast lane configuration changed"
        [[ "$FORCE_RESTART" == "1" ]] && need_restart "FORCE_RESTART=1"

        if (( ${#RESTART_REASONS[@]} == 0 )); then
            ok "Nothing changed that needs a restart; concert keeps running"
            return
        fi
        local IFS=', '
        warn "Restarting concert (${RESTART_REASONS[*]}): the queue, bans, portal settings and history are saved and restored"
        systemctl restart concert
        RESTARTED=1
    fi
    record_env
}

# ── Verification ─────────────────────────────────────────────────────

# Matches denials against the confined domain, its files, and systemd's
# pre-exec child, which is named "(concert)" and still runs as init_t.
report_avcs() {
    selinux_active && command -v ausearch &>/dev/null || return 0
    local avcs

    avcs=$(timeout 15 ausearch --input-logs -m AVC,USER_AVC,SELINUX_ERR -ts recent </dev/null 2>/dev/null \
            | grep -E 'concert_(t|exec_t|var_lib_t|etc_t)|comm="\(?concert\)?"|name="concert"' || true)

    if [[ -n "$avcs" ]]; then
        warn "SELinux denials involving concert:"
        echo "$avcs" | tail -n 20 >&2
        echo "  Inspect:  ausearch -m AVC -ts recent | audit2why" >&2
        echo "  A denied name_bind means a listen port concert may not use: label it with" >&2
        echo "  semanage port -a -t concert_port_t -p tcp <port>, or SELINUX_ANY_PORT=1" >&2
        echo "  A denied read of NADDR_DATA means its directory lacks concert_var_lib_t: re-run the installer" >&2
        echo "  A denied read of fastlane.json or networks.json means it lacks concert_etc_t, and a denied" >&2
        echo "  name_connect means a chain endpoint port nobody labeled: re-run the installer to fix both" >&2
        return 1
    fi
    ok "No audited SELinux denials for concert (semodule -DB reveals dontaudit rules; semodule -B restores)"
}

IPINFO_LINE=""

verify() {
    (( RESTARTED )) && sleep 2
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

    IPINFO_LINE=$(journalctl -u concert -n 500 --no-pager -o cat 2>/dev/null | grep 'ipinfo:' | tail -n 1 || true)
    if [[ -n "$IPINFO_LINE" ]]; then
        IPINFO_LINE="${IPINFO_LINE#*ipinfo: }"
        ok "IP details: $IPINFO_LINE"
    fi

    local port code url domain host
    local insecure=()
    port=$(port_of_addr "$LISTEN")
    domain=$(env_get CONCERT_TLS_DOMAINS)
    settings_override tls_domains domain >/dev/null
    domain="${domain%%,*}"
    domain="${domain// /}"

    if [[ -n "$domain" ]]; then
        # The first HTTPS request is what triggers certificate issuance.
        [[ "$(env_get CONCERT_TLS_STAGING)" == "true" ]] && insecure=(-k)
        url="https://$domain:$port/"
        log "Requesting $url (the first request obtains the certificate)"
        code=$(curl -s "${insecure[@]}" -o /dev/null -w '%{http_code}' --max-time 6 --resolve "$domain:$port:127.0.0.1" "$url" || true)
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

    [[ "$NADDR_DOWNLOAD" == "0" || "$NADDR_DOWNLOAD" == "1" ]] || die "NADDR_DOWNLOAD must be 0 or 1"

    resolve_binary
    ensure_user
    write_env_file
    load_installer_settings

    for p in "$(port_of_addr "$LISTEN")" "$(port_of_url "$UPSTREAM")" "$(port_of_addr "$PORTAL_LISTEN")"; do
        valid_port "$p" || die "invalid port '$p' in $ENV_FILE or $DATA_DIR/settings.json"
    done
    local naddr_port=""
    if [[ -n "$NADDR_REMOTE" ]]; then
        naddr_port=$(port_of_url "$(naddr_url "$NADDR_REMOTE")")
        valid_port "$naddr_port" || die "invalid port '$naddr_port' in NADDR_ADDR=$NADDR_REMOTE"
    fi

    if selinux_active; then
        load_policy
        apply_selinux_boolean
        for p in $(listen_ports); do
            label_port "$p" concert_port_t http_port_t http_cache_port_t
        done
        label_port "$(port_of_url "$UPSTREAM")" concert_upstream_port_t http_port_t http_cache_port_t
        if [[ -n "$naddr_port" ]]; then
            label_port "$naddr_port" concert_upstream_port_t http_port_t http_cache_port_t
        fi
    elif [[ -n "$ANY_PORT" ]]; then
        warn "SELINUX_ANY_PORT has no effect while SELinux is disabled"
    fi

    install_fastlane
    selinux_active && label_fastlane_ports

    ensure_state_dir
    install_naddr_data
    install_binary
    preflight_exec
    write_examples
    write_unit
    open_firewall

    apply_service
    verify

    local anyport="n/a (SELinux disabled)"
    selinux_active && anyport=$(getsebool "$SEBOOL" 2>/dev/null | awk '{print $NF}')

    local ipdata="off (NADDR_DATA and NADDR_ADDR are empty)"
    if [[ -n "$NADDR_PATH" ]]; then
        ipdata="$NADDR_PATH"
        [[ "$NADDR_DOWNLOAD" == "1" ]] && ipdata+="  (refreshed daily by concert-naddr-data.timer)"
    elif [[ -n "$NADDR_REMOTE" ]]; then
        ipdata="naddr service at $NADDR_REMOTE"
    fi

    echo
    echo "${BOLD}concert is installed.${RESET}"
    echo "  binary:   $BIN  (from $BINARY_SRC)"
    echo "  listen:   $LISTEN  ->  $UPSTREAM"
    echo "  portal:   $PORTAL_LISTEN"
    echo "  ports:    $(listen_ports | paste -sd, -) may be listened on${EXTRA_PORTS:+ (extra: $EXTRA_PORTS)}"
    echo "  any port: $SEBOOL is $anyport"
    echo "  ip data:  $ipdata"
    case "$FASTLANE_STATE" in
        on)       echo "  wallets:  on  ($FASTLANE_FILE, $NETWORKS_FILE; journal $DATA_DIR/gateway)" ;;
        disabled) echo "  wallets:  configured, \"enabled\": false in $FASTLANE_FILE" ;;
        *)        echo "  wallets:  off  (samples in $ETC/*.example.json; see docs/FASTLANE.md)" ;;
    esac
    [[ -n "$IPINFO_LINE" ]] && echo "            concert says: $IPINFO_LINE"
    echo "  config:   $ENV_FILE  (portal changes: $DATA_DIR/settings.json)"
    echo "  data:     $DATA_DIR  (settings.json, bans.json, queue.snapshot, history.jsonl, fastlane.jsonl, gateway/)"
    echo "  state:    $STATE_DIR"
    echo "  logs:     journalctl -u concert -f"
    if (( ! RESTARTED )); then
        echo "  service:  kept running (no restart needed)"
    fi
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
    systemctl disable --now concert-naddr-data.timer 2>/dev/null || true
    rm -f -- "$UNIT" "$NADDR_SERVICE" "$NADDR_TIMER" "$NADDR_UPDATER"
    systemctl daemon-reload

    if [[ -f "$STATE" ]]; then
        while read -r kind port; do
            case "$kind" in
                port)
                    selinux_active && semanage port -d -p tcp "$port" 2>/dev/null \
                        && ok "Removed label on tcp/$port" ;;
                fcontext)
                    selinux_active && semanage fcontext -d "$port" 2>/dev/null \
                        && ok "Removed file context rule $port" ;;
                fw)
                    systemctl is-active --quiet firewalld \
                        && firewall-cmd --quiet --permanent --remove-port="$port/tcp" \
                        && firewall-cmd --quiet --reload \
                        && ok "Closed tcp/$port in firewalld" ;;
            esac
        done < "$STATE"
        rm -f -- "$STATE"
    fi
    rm -f -- "$ENV_SUM"

    # Port labels must go before the module, or semodule refuses to remove it.
    # The concert_bind_any_port boolean goes with the module.
    if selinux_active && semodule -l | grep -qE "^${MODULE}([[:space:]]|$)"; then
        semodule -r "$MODULE" && ok "Removed SELinux module $MODULE"
    fi

    rm -f -- "$BIN"
    ok "Removed $BIN and the IPtoASN refresh timer"

    if [[ "$PURGE" == "1" ]]; then
        rm -rf -- "$ETC" "$STATE_DIR"
        getent passwd "$SVC_USER" >/dev/null && userdel "$SVC_USER"
        ok "Purged $ETC, $STATE_DIR (settings, bans, history and the IPtoASN database) and user $SVC_USER"
    else
        echo "  Kept $ETC, $STATE_DIR (settings, bans, history, the IPtoASN database) and user $SVC_USER (PURGE=1 removes them)"
    fi
}

# ── Main ─────────────────────────────────────────────────────────────

case "${1:-install}" in
    install)   do_install ;;
    uninstall) do_uninstall ;;
    *)         die "usage: $0 [install|uninstall]" ;;
esac