#!/bin/sh
# Make a step-ca-enrolled host a vigil-respond target. Run as root on the host:
#
#   sh install.sh --principal sa-vigil-responder --never-block 10.0.0.1,192.0.2.0/24
#
# It requires the host's step-ca enrollment (TrustedUserCAKeys and AuthorizedPrincipalsFile in
# /etc/ssh/sshd_config.d): it never opens SSH by itself. It adds:
#   - the user vigil-responder: no password, no home contents;
#   - /usr/local/sbin/vigil-respond (the forced command) and vigil-respond-nft (the root helper);
#   - one sudo rule: vigil-responder may run vigil-respond-nft as root, nothing else;
#   - /etc/ssh/auth_principals/vigil-responder: the principal, with restrict and command=, so the
#     account cannot get a shell even if a certificate had no force-command;
#   - /etc/vigil-respond/never-block: addresses that are never blocked (loopback, the ones you
#     give, and this host's own addresses);
#   - vigil-respond.service: creates the nftables table at boot. Blocks do not survive a reboot.
# Run it again to update. --uninstall removes all of it and the nftables table.
set -eu
PRINCIPAL=sa-vigil-responder
NEVER=""
UNINSTALL=0
HERE=$(cd "$(dirname "$0")" && pwd)
while [ $# -gt 0 ]; do
  case "$1" in
    --principal) PRINCIPAL=$2; shift 2 ;;
    --never-block) NEVER=$2; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 2; }
case "$PRINCIPAL" in sa-*) ;; *) echo "--principal must be the responder's sa-... account" >&2; exit 2 ;; esac

if [ "$UNINSTALL" -eq 1 ]; then
  systemctl disable --now vigil-respond.service 2>/dev/null || true
  rm -f /etc/systemd/system/vigil-respond.service /etc/sudoers.d/60-vigil-respond \
        /etc/ssh/auth_principals/vigil-responder /usr/local/sbin/vigil-respond /usr/local/sbin/vigil-respond-nft
  rm -rf /etc/vigil-respond
  nft delete table inet vigil_respond 2>/dev/null || true
  userdel vigil-responder 2>/dev/null || true
  echo "vigil-respond removed"; exit 0
fi

grep -qs '^TrustedUserCAKeys' /etc/ssh/sshd_config.d/*.conf && \
  grep -qs '^AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u' /etc/ssh/sshd_config.d/*.conf || {
  echo "this host is not enrolled with step-ca (scripts/enroll-host.sh): no TrustedUserCAKeys or" >&2
  echo "AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u in /etc/ssh/sshd_config.d" >&2; exit 1; }
command -v nft >/dev/null || { echo "nft (nftables) is required" >&2; exit 1; }
command -v sudo >/dev/null || { echo "sudo is required" >&2; exit 1; }

id vigil-responder >/dev/null 2>&1 || useradd --system --no-create-home --home-dir / \
  --shell /bin/sh --comment "vigil-respond (step-ca certificate only)" vigil-responder
passwd -l vigil-responder >/dev/null 2>&1 || true

install -o root -g root -m 0755 "$HERE/vigil-respond" /usr/local/sbin/vigil-respond
install -o root -g root -m 0755 "$HERE/vigil-respond-nft" /usr/local/sbin/vigil-respond-nft

tmp=$(mktemp)
echo 'vigil-responder ALL=(root) NOPASSWD: /usr/local/sbin/vigil-respond-nft' > "$tmp"
visudo -cqf "$tmp" || { rm -f "$tmp"; echo "sudo rule check failed" >&2; exit 1; }
install -o root -g root -m 0440 "$tmp" /etc/sudoers.d/60-vigil-respond; rm -f "$tmp"

install -d -o root -g root -m 0755 /etc/ssh/auth_principals
printf 'restrict,command="/usr/local/sbin/vigil-respond" %s\n' "$PRINCIPAL" > /etc/ssh/auth_principals/vigil-responder
chmod 0644 /etc/ssh/auth_principals/vigil-responder

install -d -o root -g root -m 0755 /etc/vigil-respond
{
  echo "# Never blocked by vigil-respond. One address or CIDR per line. Written by install.sh."
  echo "127.0.0.0/8"
  echo "::1/128"
  for a in $(hostname -I 2>/dev/null); do echo "$a  # this host"; done
  [ -n "$NEVER" ] && printf '%s\n' "$NEVER" | tr ',' '\n'
} > /etc/vigil-respond/never-block
chmod 0644 /etc/vigil-respond/never-block

cat > /etc/systemd/system/vigil-respond.service <<'UNIT'
[Unit]
Description=vigil-respond nftables table (blocks with timeouts)
After=network-pre.target nftables.service
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vigil-respond-nft check
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now vigil-respond.service >/dev/null
/usr/local/sbin/vigil-respond-nft check >/dev/null
echo "vigil-respond installed for principal $PRINCIPAL. Never-block list: /etc/vigil-respond/never-block"
