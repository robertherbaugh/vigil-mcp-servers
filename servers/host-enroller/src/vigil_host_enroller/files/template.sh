#!/bin/sh
# Prepare a VM template (for example Ubuntu 26.04) so each clone enrolls itself at first boot.
# Served by vigil-host-enroller. Run as root in the template VM, then shut it down and convert it:
#
#   curl -fsSL https://enroll.herbaugh.network/template.sh | sh
#
# It installs qemu-guest-agent and the first-boot unit, and it does not enroll the template.
# In Proxmox, give the template the tag step-enroll and turn on "QEMU Guest Agent": clones copy
# both. Every clone of it can then enroll itself, so tag only templates that you trust.
set -eu
ENROLLER=@@ENROLLER@@
SHA_FIRSTBOOT=@@SHA_FIRSTBOOT@@
fail() { echo "template: FAILED: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail "run as root"
if ! [ -e /usr/sbin/qemu-ga ] && ! [ -e /usr/bin/qemu-ga ]; then
  if command -v apt-get >/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends qemu-guest-agent >/dev/null
  elif command -v dnf >/dev/null; then dnf install -y -q qemu-guest-agent
  else fail "install qemu-guest-agent first"; fi
fi
tmp=$(mktemp)
curl -fsS --proto '=https' --tlsv1.2 -o "$tmp" "$ENROLLER/files/vigil-enroll-firstboot.service"
[ "$(sha256sum "$tmp" | cut -d' ' -f1)" = "$SHA_FIRSTBOOT" ] || { rm -f "$tmp"; fail "wrong SHA-256"; }
install -m 0644 "$tmp" /etc/systemd/system/vigil-enroll-firstboot.service; rm -f "$tmp"
install -d -m 0755 /etc/vigil-enroll
printf 'ENROLLER=%s\n' "$ENROLLER" >/etc/vigil-enroll/template
# A template that was enrolled must not pass that on: each clone enrolls with its own keys.
rm -f /etc/vigil-enroll/enrolled /etc/vigil-enroll/config
systemctl daemon-reload
systemctl enable vigil-enroll-firstboot.service >/dev/null
echo "template: ready. Before you convert it: cloud-init clean --machine-id --seed --logs,"
echo "and delete /etc/ssh/ssh_host_* so that each clone makes its own host keys."
