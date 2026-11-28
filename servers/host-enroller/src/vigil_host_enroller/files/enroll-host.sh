#!/usr/bin/env bash
# Copy of homelab-docker-k8s kubernetes/apps/step-ca/scripts/enroll-host.sh (f83b64e), plus
# --host-principal. bootstrap.sh runs it. Keep the two copies equal.
# Make a Linux host trust step-ca for SSH logins (run as root on the host). It only adds:
#   - /etc/ssh/step_user_ca.pub: the SSH user CA key (from the CA, checked against the root).
#   - /etc/ssh/sshd_config.d/40-step-ca.conf: TrustedUserCAKeys and AuthorizedPrincipalsFile.
#   - /etc/ssh/auth_principals/<user>: which certificate principals may log in as <user>.
#   - optional: the local users automation and automation-sudo, sudo rules, and a host certificate
#     with a weekly renewal timer.
# authorized_keys stays as it is: the existing keys (and the break-glass key) keep working.
# sshd -t checks the new configuration before the reload. A failure restores the old one.
set -euo pipefail

CA_URL=https://ca.herbaugh.network
FINGERPRINT=""
HOST_TOKEN=""
ADMIN_USER=""
AUTOMATION=0
AUTOMATION_SUDO=0
SUDO_COMMANDS="ALL"
declare -a MAPS=()
declare -a HOST_PRINCIPALS=()

usage() {
  cat >&2 <<'EOF'
usage: enroll-host.sh --fingerprint ROOT_FP [options]
  --ca-url URL              step-ca (default https://ca.herbaugh.network)
  --fingerprint FP          root certificate fingerprint (README "Public values")
  --admin-user USER         people in ssh-admins (principal "admin") log in as USER, for example root
  --automation              user "automation" (no sudo) for principal "automation"
  --automation-sudo         user "automation-sudo" for principal "automation-sudo", with sudo
  --sudo-commands LIST      sudo rule for automation-sudo (default ALL), for example
                            "/usr/bin/systemctl restart nginx, /usr/bin/apt-get update"
  --map PRINCIPAL:USER      also let PRINCIPAL log in as USER (repeat). Examples:
                            robert-herbaugh:robert (a person), sa-backup:backup (one account only)
  --host-token TOKEN        sign this host's SSH key: a one-time token from
                            `step ca token --ssh --host` (README "Enroll a host")
  --host-principal NAME     put NAME in the host certificate too (repeat). Each one must be in
                            the token. Default: the token's subject only
EOF
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --ca-url) CA_URL=$2; shift 2 ;;
    --fingerprint) FINGERPRINT=$2; shift 2 ;;
    --admin-user) ADMIN_USER=$2; shift 2 ;;
    --automation) AUTOMATION=1; shift ;;
    --automation-sudo) AUTOMATION_SUDO=1; shift ;;
    --sudo-commands) SUDO_COMMANDS=$2; shift 2 ;;
    --map) MAPS+=("$2"); shift 2 ;;
    --host-token) HOST_TOKEN=$2; shift 2 ;;
    --host-principal) HOST_PRINCIPALS+=(--principal "$2"); shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown option $1" >&2; usage ;;
  esac
done

fail() { echo "FAILED: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail "run as root"
[ -n "$FINGERPRINT" ] || usage
command -v step >/dev/null || fail "install the step CLI first (README \"Enroll a host\")"
command -v sshd >/dev/null || [ -x /usr/sbin/sshd ] || fail "no sshd on this host"
SSHD=$(command -v sshd || echo /usr/sbin/sshd)
grep -Eqi '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config ||
  fail "/etc/ssh/sshd_config does not include sshd_config.d/*.conf. Add that line at the top first."
if [ "$AUTOMATION_SUDO" = 1 ]; then command -v visudo >/dev/null || fail "install sudo first (apt-get install sudo)"; fi

# Principals file per user. Each line is one principal.
declare -A PRINCIPALS=()
add_map() {
  local principal=${1%%:*} user=${1#*:}
  [[ "$principal" =~ ^[a-z0-9_][a-z0-9_.-]*$ ]] || fail "bad principal $principal"
  [[ "$user" =~ ^[a-z_][a-z0-9_-]*$ ]] || fail "bad user $user"
  [ "$principal" != root ] || fail "the CA never signs the principal root. Use --admin-user root."
  PRINCIPALS[$user]+="$principal"$'\n'
}
[ -n "$ADMIN_USER" ] && add_map "admin:$ADMIN_USER"
[ "$AUTOMATION" = 1 ] && add_map "automation:automation"
[ "$AUTOMATION_SUDO" = 1 ] && add_map "automation-sudo:automation-sudo"
for m in "${MAPS[@]}"; do add_map "$m"; done
[ "${#PRINCIPALS[@]}" -gt 0 ] || fail "nothing to do: give --admin-user, --automation, --automation-sudo or --map"

export STEPPATH=/etc/step
umask 022
echo "1. Trust the CA (root fingerprint $FINGERPRINT)"
step ca bootstrap --ca-url "$CA_URL" --fingerprint "$FINGERPRINT" --force >/dev/null
# The user CA key, from the CA over TLS that the pinned root checks. One key per line.
step ssh config --roots >/etc/ssh/step_user_ca.pub.new
grep -q '^ecdsa-\|^ssh-' /etc/ssh/step_user_ca.pub.new || fail "the CA returned no SSH user CA key"

echo "2. Local users and sudo"
make_user() {
  id "$1" >/dev/null 2>&1 && return
  useradd --create-home --shell /bin/bash --comment "step-ca $1 (certificate logins only)" "$1"
  # "*" is no password at all. "!" (locked) can also block key and certificate logins.
  usermod -p '*' "$1"
  echo "   created user $1"
}
[ "$AUTOMATION" = 1 ] && make_user automation
if [ "$AUTOMATION_SUDO" = 1 ]; then
  make_user automation-sudo
  rule=/etc/sudoers.d/50-step-ca-automation-sudo
  printf '# step-ca: principal automation-sudo (Authentik group ssh-automation-sudo).\nautomation-sudo ALL=(ALL:ALL) NOPASSWD: %s\n' "$SUDO_COMMANDS" >"$rule.new"
  chmod 0440 "$rule.new"
  visudo -cqf "$rule.new" || { rm -f "$rule.new"; fail "the sudo rule does not parse: $SUDO_COMMANDS"; }
  mv "$rule.new" "$rule"
  echo "   sudo for automation-sudo: $SUDO_COMMANDS"
fi
for user in "${!PRINCIPALS[@]}"; do id "$user" >/dev/null 2>&1 || fail "no local user $user (make it first)"; done

echo "3. sshd: trust user certificates, map principals to users"
backup=$(mktemp -d)
cp -a /etc/ssh/. "$backup/"
restore() { echo "   restoring /etc/ssh" >&2; rm -rf /etc/ssh/sshd_config.d/40-step-ca.conf /etc/ssh/auth_principals; cp -a "$backup/." /etc/ssh/; }
mv /etc/ssh/step_user_ca.pub.new /etc/ssh/step_user_ca.pub
mkdir -p /etc/ssh/auth_principals
for user in "${!PRINCIPALS[@]}"; do
  printf '%s' "${PRINCIPALS[$user]}" | sort -u >"/etc/ssh/auth_principals/$user"
  echo "   $user <- $(paste -sd, "/etc/ssh/auth_principals/$user")"
done
chmod 0644 /etc/ssh/step_user_ca.pub /etc/ssh/auth_principals/*
{
  echo "# step-ca (kubernetes/apps/step-ca). A certificate logs in as <user> only if one of its"
  echo "# principals is in /etc/ssh/auth_principals/<user>. authorized_keys still works."
  echo "TrustedUserCAKeys /etc/ssh/step_user_ca.pub"
  echo "AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u"
} >/etc/ssh/sshd_config.d/40-step-ca.conf

key=/etc/ssh/ssh_host_ed25519_key
if [ -z "$HOST_TOKEN" ] && [ -f "$key-cert.pub" ]; then
  # A second run without a token keeps the host certificate from the first run.
  echo "HostCertificate $key-cert.pub" >>/etc/ssh/sshd_config.d/40-step-ca.conf
fi
if [ -n "$HOST_TOKEN" ]; then
  echo "4. Host certificate"
  [ -f "$key.pub" ] || fail "no $key.pub"
  # The certificate's subject must be the token's own subject (step-ca refuses any other), so it
  # comes from the token, not from this host's name: a host with no DNS name enrolls by IP
  # (README "Enroll a host"). step reads the token without checking its signature; the CA checks.
  subject=$(printf %s "$HOST_TOKEN" | step crypto jwt inspect --insecure 2>/dev/null |
    sed -n 's/^ *"sub": *"\([^"]*\)".*/\1/p' | head -1)
  [ -n "$subject" ] || { restore; fail "the host token is not a JWT with a subject (pasted in full?)"; }
  echo "   subject $subject"
  if ! out=$(step ssh certificate --host --sign --token "$HOST_TOKEN" --force ${HOST_PRINCIPALS[@]+"${HOST_PRINCIPALS[@]}"} "$subject" "$key.pub" 2>&1); then
    restore
    fail "the CA refused the host token (expired or already used?): $(printf %s "$out" | tail -1)"
  fi
  echo "HostCertificate $key-cert.pub" >>/etc/ssh/sshd_config.d/40-step-ca.conf
  # Renew weekly with the current certificate (SSHPOP provisioner). It lasts 30 days.
  cat >/etc/systemd/system/step-ssh-renew.service <<EOF
[Unit]
Description=Renew the SSH host certificate (step-ca)
[Service]
Type=oneshot
Environment=STEPPATH=/etc/step
ExecStart=$(command -v step) ssh renew --force $key-cert.pub $key
# Debian names the unit ssh.service, RHEL sshd.service.
ExecStartPost=/bin/sh -c 'systemctl reload ssh.service 2>/dev/null || systemctl reload sshd.service'
EOF
  cat >/etc/systemd/system/step-ssh-renew.timer <<'EOF'
[Unit]
Description=Renew the SSH host certificate weekly (step-ca)
[Timer]
OnCalendar=weekly
RandomizedDelaySec=6h
Persistent=true
[Install]
WantedBy=timers.target
EOF
  if [ -d /run/systemd/system ]; then systemctl daemon-reload && systemctl enable --now step-ssh-renew.timer >/dev/null; fi
fi

"$SSHD" -t || { restore; fail "sshd -t refused the new configuration"; }
# The effective settings. Read them into a variable first: grep -q in a pipe ends early, and
# pipefail then reports the SIGPIPE of sshd as a failure.
effective=$("$SSHD" -T -C user=root,host=localhost,addr=127.0.0.1 2>/dev/null || true)
grep -qix "trustedusercakeys /etc/ssh/step_user_ca.pub" <<<"$effective" &&
  grep -qix "authorizedprincipalsfile /etc/ssh/auth_principals/%u" <<<"$effective" ||
  { restore; fail "sshd does not use 40-step-ca.conf: an earlier file sets TrustedUserCAKeys or AuthorizedPrincipalsFile"; }
if [ -d /run/systemd/system ]; then
  systemctl reload ssh.service 2>/dev/null || systemctl reload sshd.service
else
  # No systemd (a container): signal sshd directly.
  pkill -HUP -x sshd || true
fi
rm -rf "$backup"
echo "Done. Test a certificate login now, in a second terminal, before you close this session."
