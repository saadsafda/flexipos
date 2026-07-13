#!/usr/bin/env bash
set -Eeuo pipefail

backup_dir=${1:?Usage: verify_backup.sh BACKUP_DIRECTORY [AGE_IDENTITY]}
age_identity=${2:-${BACKUP_AGE_IDENTITY:-}}
[[ -d "$backup_dir" ]] || { echo "Backup directory not found: $backup_dir" >&2; exit 2; }

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/flexipos-verify.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT INT TERM

if [[ -f "$backup_dir/SHA256SUMS.age" ]]; then
  command -v age >/dev/null || { echo "age is required to verify this backup" >&2; exit 2; }
  [[ -n "$age_identity" ]] || { echo "Provide the age identity file" >&2; exit 2; }
  for file in database.sql.gz public-files.tgz private-files.tgz site-config.json SHA256SUMS; do
    age --decrypt --identity "$age_identity" \
      --output "$work_dir/$file" "$backup_dir/$file.age"
  done
else
  for file in database.sql.gz public-files.tgz private-files.tgz site-config.json SHA256SUMS; do
    cp "$backup_dir/$file" "$work_dir/$file"
  done
fi

(cd "$work_dir" && {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum --check SHA256SUMS
  else
    shasum -a 256 --check SHA256SUMS
  fi
})
gzip -t "$work_dir/database.sql.gz"
tar -tzf "$work_dir/public-files.tgz" >/dev/null
tar -tzf "$work_dir/private-files.tgz" >/dev/null
python3 -m json.tool "$work_dir/site-config.json" >/dev/null
echo "Backup is readable and all checksums match"
