#!/usr/bin/env bash
# Check, and optionally enable, persistent journald storage on a monitored Linux host.
#
# Default is a read-only check. With --apply (as root) it:
#   - writes /etc/systemd/journald.conf.d/90-defensync-persistent.conf (Storage=persistent, size cap)
#   - creates /var/log/journal with the distribution's tmpfiles ownership/ACLs
#   - restarts systemd-journald and flushes the in-memory journal to disk
# Existing journald.conf and other drop-ins are not edited. Remove the drop-in to revert.
#
# Usage: enable_persistent_journal.sh [--apply] [--max-use SIZE]   (SIZE default 500M)
set -euo pipefail

DROPIN_DIR=/etc/systemd/journald.conf.d
DROPIN="$DROPIN_DIR/90-defensync-persistent.conf"
MAX_USE=500M
APPLY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --apply) APPLY=1 ;;
    --max-use) MAX_USE="${2:?--max-use needs a value such as 500M}"; shift ;;
    -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
case "$MAX_USE" in *[!0-9KMGT]*|"") echo "invalid --max-use: $MAX_USE" >&2; exit 2 ;; esac

storage="$(systemd-analyze cat-config systemd/journald.conf 2>/dev/null \
  | sed -n 's/^[[:space:]]*Storage=[[:space:]]*//p' | tail -n 1)"
storage="${storage:-auto (default)}"
dir_state=$([ -d /var/log/journal ] && echo present || echo missing)
boots="$(journalctl --list-boots -q --no-pager 2>/dev/null | grep -cE '[0-9a-f]{32}' || true)"

echo "journald Storage setting : $storage"
echo "/var/log/journal         : $dir_state"
echo "boots in journal         : ${boots:-unknown}"
case "$storage" in
  persistent*) persistent=yes ;;
  volatile*|none*) persistent=no ;;
  *) persistent=$([ "$dir_state" = present ] && echo yes || echo no) ;;
esac
echo "persistent across reboot : $persistent"

if [ "$APPLY" -eq 0 ]; then
  if [ "$persistent" = yes ]; then
    echo "Nothing to do."
  else
    echo "Dry run. To enable persistent storage run as root: $0 --apply [--max-use $MAX_USE]"
  fi
  exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "--apply must run as root (e.g. sudo $0 --apply)" >&2
  exit 1
fi

mkdir -p "$DROPIN_DIR"
cat > "$DROPIN" <<EOF
# Managed by DefenSync: keep the journal across reboots so incremental collection has no gaps.
[Journal]
Storage=persistent
SystemMaxUse=$MAX_USE
EOF
chmod 0644 "$DROPIN"
mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal
systemctl restart systemd-journald
journalctl --flush
echo "Wrote $DROPIN; journal now stored in /var/log/journal (cap $MAX_USE)."
journalctl --disk-usage
