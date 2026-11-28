#!/bin/sh
# Enroll this VM with step-ca and make it a Vigil responder host. Served by vigil-host-enroller,
# which fills in the values below. Run as root:
#
#   curl -fsSL https://enroll.herbaugh.network/bootstrap.sh | sh
#
# The enroller trusts no claim in this script: it checks the TCP source address, the Proxmox tag
# and the SMBIOS UUID against Proxmox (README "How a VM proves itself"). Then:
#   1. packages: bash, curl, sudo, nftables, qemu-guest-agent (apt or dnf), and the step CLI
#   2. a one-time host token from the enroller
#   3. enroll-host.sh: trust the SSH user CA, a host certificate, weekly renewal
#   4. the responder kit (vigil-respond), with the gateway on its never-block list
#   5. vigil-enroll-report: a timer that tells the enroller each day that the kit is ready
# Safe to run again. It changes nothing when a check fails before step 3. Each request has a
# connect timeout of 10 s, so a network that drops the connection fails fast and tries again.
set -eu
ENROLLER=@@ENROLLER@@
CA_URL=@@CA_URL@@
FINGERPRINT=@@FINGERPRINT@@
ENROLL_ARGS=@@ENROLL_ARGS@@
KIT_PRINCIPAL=@@KIT_PRINCIPAL@@
KIT_NEVER_BLOCK=@@KIT_NEVER_BLOCK@@
KIT_VERSION=@@KIT_VERSION@@
SHA_STEP=@@SHA_STEP@@
SHA_KIT=@@SHA_KIT@@
SHA_ENROLL=@@SHA_ENROLL@@
SHA_REPORT=@@SHA_REPORT@@
SHA_REPORT_SERVICE=@@SHA_REPORT_SERVICE@@
SHA_REPORT_TIMER=@@SHA_REPORT_TIMER@@

say() { echo "vigil-enroll: $*"; }
fail() { echo "vigil-enroll: FAILED: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail "run as root"
[ -r /sys/class/dmi/id/product_uuid ] || fail "no SMBIOS UUID: this is not a Proxmox (QEMU) VM"
UUID=$(tr 'A-Z' 'a-z' </sys/class/dmi/id/product_uuid)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

fetch() { # fetch NAME SHA256 DEST
  curl -fsS --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 300 --retry 3 -o "$3" "$ENROLLER/files/$1" || fail "cannot download $1"
  [ "$(sha256sum "$3" | cut -d' ' -f1)" = "$2" ] || fail "$1: wrong SHA-256"
}
post() { # post PATH JSON -> body on stdout; fails with the enroller's reason
  code=$(curl -sS --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 60 -o "$work/answer" -w '%{http_code}' \
    -H 'Content-Type: application/json' --data "$2" "$ENROLLER$1") || fail "cannot reach $ENROLLER"
  [ "$code" = 200 ] || fail "the enroller refused ($code): $(head -c 300 "$work/answer")"
  cat "$work/answer"
}

say "1. Packages"
need=""
command -v bash >/dev/null || need="$need bash"
command -v sudo >/dev/null || need="$need sudo"
command -v nft >/dev/null || need="$need nftables"
command -v sshd >/dev/null || [ -x /usr/sbin/sshd ] || need="$need openssh-server"
[ -e /usr/sbin/qemu-ga ] || [ -e /usr/bin/qemu-ga ] || need="$need qemu-guest-agent"
if [ -n "$need" ]; then
  say "   installing$need"
  if command -v apt-get >/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq && \
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends $need >/dev/null
  elif command -v dnf >/dev/null; then
    dnf install -y -q $need
  else
    fail "install$need first"
  fi
fi
# The enroller finds this VM through the agent. Ubuntu starts it from udev when Proxmox gives the
# VM the agent's serial port (VM option "QEMU Guest Agent"). Start it now in case it is not up.
systemctl start qemu-guest-agent.service 2>/dev/null || true
if ! command -v step >/dev/null; then
  [ "$(uname -m)" = x86_64 ] || fail "install the step CLI first (the enroller has it for x86_64 only)"
  fetch step "$SHA_STEP" "$work/step"
  install -m 0755 "$work/step" /usr/local/bin/step
  say "   step CLI $(/usr/local/bin/step version 2>/dev/null | head -1)"
fi

say "2. Host token (VM $UUID)"
# Proxmox reads the agent's addresses. A VM that just booted may need a moment.
tries=0
until answer=$(post /v1/enroll "{\"uuid\":\"$UUID\"}" 2>"$work/err"); do
  tries=$((tries + 1))
  [ "$tries" -lt 6 ] || { cat "$work/err" >&2; exit 1; }
  sleep 10
done
TOKEN=$(printf '%s\n' "$answer" | sed -n 1p)
PRINCIPALS=$(printf '%s\n' "$answer" | sed -n 2p)
say "   principals: $PRINCIPALS"

say "3. step-ca enrollment"
fetch enroll-host.sh "$SHA_ENROLL" "$work/enroll-host.sh"
set --
for p in $PRINCIPALS; do set -- "$@" --host-principal "$p"; done
# shellcheck disable=SC2086 # ENROLL_ARGS is a list of options from the enroller's configuration
bash "$work/enroll-host.sh" --ca-url "$CA_URL" --fingerprint "$FINGERPRINT" --host-token "$TOKEN" \
  "$@" $ENROLL_ARGS

say "4. Responder kit $KIT_VERSION"
fetch kit.tar.gz "$SHA_KIT" "$work/kit.tar.gz"
tar -xzf "$work/kit.tar.gz" -C "$work"
gateway=$(ip -4 route show default 2>/dev/null | awk '{print $3; exit}')
never=$(printf '%s,%s' "$gateway" "$KIT_NEVER_BLOCK" | sed 's/^,//; s/,$//')
sh "$work/kit/install.sh" --principal "$KIT_PRINCIPAL" --never-block "$never"

say "5. Daily report"
install -d -m 0755 /etc/vigil-enroll
printf 'ENROLLER=%s\nKIT_VERSION=%s\n' "$ENROLLER" "$KIT_VERSION" >/etc/vigil-enroll/config
fetch vigil-enroll-report "$SHA_REPORT" "$work/report"
install -m 0755 "$work/report" /usr/local/sbin/vigil-enroll-report
fetch vigil-enroll-report.service "$SHA_REPORT_SERVICE" /etc/systemd/system/vigil-enroll-report.service
fetch vigil-enroll-report.timer "$SHA_REPORT_TIMER" /etc/systemd/system/vigil-enroll-report.timer
systemctl daemon-reload
systemctl enable --now vigil-enroll-report.timer >/dev/null
/usr/local/sbin/vigil-enroll-report
date -u +%FT%TZ >/etc/vigil-enroll/enrolled
say "done: enrolled as $PRINCIPALS. Test a certificate login in a second terminal."
