#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

backup_env_file=${FLEXIPOS_BACKUP_ENV_FILE:-/etc/flexipos/backup.env}
if [[ -f "$backup_env_file" ]]; then
  # This file must be root-owned and non-writable by the service account.
  set -a
  # shellcheck disable=SC1090
  source "$backup_env_file"
  set +a
fi

SITE=${SITE:?Set SITE to the Frappe site name}
BENCH_PATH=${BENCH_PATH:-/home/frappe/frappe-bench}
BACKUP_ROOT=${BACKUP_ROOT:-/var/backups/flexipos}
BACKUP_ENCRYPTION=${BACKUP_ENCRYPTION:-age}
BACKUP_AGE_RECIPIENT=${BACKUP_AGE_RECIPIENT:-}
RCLONE_REMOTE=${RCLONE_REMOTE:-}
REQUIRE_OFFSITE=${REQUIRE_OFFSITE:-0}
RETENTION_DAYS=${RETENTION_DAYS:-30}

[[ "$SITE" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "Invalid site name" >&2; exit 2; }
[[ "$BENCH_PATH" == /* && "$BACKUP_ROOT" == /* ]] || {
  echo "BENCH_PATH and BACKUP_ROOT must be absolute paths" >&2
  exit 2
}
[[ "$RETENTION_DAYS" =~ ^[0-9]+$ ]] || { echo "RETENTION_DAYS must be numeric" >&2; exit 2; }
if [[ "$REQUIRE_OFFSITE" == 1 && -z "$RCLONE_REMOTE" ]]; then
  echo "RCLONE_REMOTE is required when REQUIRE_OFFSITE=1" >&2
  exit 2
fi
if [[ "$BACKUP_ENCRYPTION" == age ]]; then
  command -v age >/dev/null || { echo "age is required for encrypted backups" >&2; exit 2; }
  [[ -n "$BACKUP_AGE_RECIPIENT" ]] || { echo "BACKUP_AGE_RECIPIENT is required" >&2; exit 2; }
elif [[ "$BACKUP_ENCRYPTION" != none ]]; then
  echo "BACKUP_ENCRYPTION must be 'age' or 'none'" >&2
  exit 2
else
  echo "WARNING: creating an explicitly unencrypted backup" >&2
fi

lock_dir="${TMPDIR:-/tmp}/flexipos-backup-${SITE}.lock"
if ! mkdir "$lock_dir" 2>/dev/null; then
  lock_pid=$(cat "$lock_dir/pid" 2>/dev/null || true)
  if [[ "$lock_pid" =~ ^[0-9]+$ ]] && kill -0 "$lock_pid" 2>/dev/null; then
    echo "Another backup is already running for $SITE (PID $lock_pid)" >&2
    exit 1
  fi
  rm -rf "$lock_dir"
  mkdir "$lock_dir"
fi
printf '%s\n' "$$" > "$lock_dir/pid"
work_dir=''
cleanup() {
  local status=$?
  [[ -z "$work_dir" || ! -d "$work_dir" ]] || rm -rf "$work_dir"
  rm -rf "$lock_dir"
  exit "$status"
}
trap cleanup EXIT INT TERM

run_bench() {
  if command -v bench >/dev/null 2>&1; then
    (cd "$BENCH_PATH" && bench "$@")
  else
    (cd "$BENCH_PATH/sites" && \
      ../env/bin/python ../apps/frappe/frappe/utils/bench_helper.py frappe "$@")
  fi
}

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
site_root="$BACKUP_ROOT/$SITE"
final_dir="$site_root/$timestamp"
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/flexipos-backup.XXXXXX")
mkdir -p "$site_root"
[[ ! -e "$final_dir" ]] || { echo "Backup already exists: $final_dir" >&2; exit 1; }

db="$work_dir/database.sql.gz"
public_files="$work_dir/public-files.tgz"
private_files="$work_dir/private-files.tgz"
site_config="$work_dir/site-config.json"

run_bench --site "$SITE" backup --with-files --compress \
  --backup-path-db "$db" \
  --backup-path-files "$public_files" \
  --backup-path-private-files "$private_files" \
  --backup-path-conf "$site_config"

gzip -t "$db"
tar -tzf "$public_files" >/dev/null
tar -tzf "$private_files" >/dev/null
python3 -m json.tool "$site_config" >/dev/null

(cd "$work_dir" && {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum database.sql.gz public-files.tgz private-files.tgz site-config.json
  else
    shasum -a 256 database.sql.gz public-files.tgz private-files.tgz site-config.json
  fi
} > SHA256SUMS)

if [[ "$BACKUP_ENCRYPTION" == age ]]; then
  for file in database.sql.gz public-files.tgz private-files.tgz site-config.json SHA256SUMS; do
    age --encrypt --recipient "$BACKUP_AGE_RECIPIENT" \
      --output "$work_dir/$file.age" "$work_dir/$file"
    rm -f "$work_dir/$file"
  done
fi

mv "$work_dir" "$final_dir"
work_dir=''

if [[ -n "$RCLONE_REMOTE" ]]; then
  command -v rclone >/dev/null || { echo "rclone is required for off-site backups" >&2; exit 2; }
  rclone copy "$final_dir" "${RCLONE_REMOTE%/}/$SITE/$timestamp" --immutable
  rclone delete "${RCLONE_REMOTE%/}/$SITE" --min-age "${RETENTION_DAYS}d"
  rclone rmdirs "${RCLONE_REMOTE%/}/$SITE" --leave-root
fi

find "$site_root" -mindepth 1 -maxdepth 1 -type d -mtime "+$RETENTION_DAYS" -exec rm -rf {} +
echo "Backup completed and verified: $final_dir"
