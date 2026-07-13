#!/usr/bin/env bash
set -Eeuo pipefail

SITE=${SITE:?Set SITE to the Frappe site name}
BENCH_PATH=${BENCH_PATH:-/home/frappe/frappe-bench}
DEPLOY_REF=${DEPLOY_REF:-version-16}
HEALTHCHECK_URL=${HEALTHCHECK_URL:?Set HEALTHCHECK_URL to the staging ping endpoint}
BACKUP_SCRIPT=${BACKUP_SCRIPT:-$BENCH_PATH/apps/flexipos/scripts/backup_site.sh}
ALLOW_NON_FF=${ALLOW_NON_FF:-0}
app_dir="$BENCH_PATH/apps/flexipos"

[[ "$SITE" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "Invalid site name" >&2; exit 2; }
[[ "$BENCH_PATH" == /* && "$BACKUP_SCRIPT" == /* ]] || {
  echo "BENCH_PATH and BACKUP_SCRIPT must be absolute paths" >&2
  exit 2
}
[[ "$HEALTHCHECK_URL" == https://* ]] || { echo "HEALTHCHECK_URL must use HTTPS" >&2; exit 2; }
command -v bench >/dev/null || { echo "bench is not available on PATH" >&2; exit 2; }
[[ -x "$BACKUP_SCRIPT" || -f "$BACKUP_SCRIPT" ]] || { echo "Backup script not found" >&2; exit 2; }
[[ -d "$app_dir/.git" ]] || { echo "FlexiPOS app repository not found" >&2; exit 2; }
[[ -z "$(git -C "$app_dir" status --porcelain)" ]] || {
  echo "Refusing to deploy over uncommitted backend changes" >&2
  exit 1
}

lock_dir="${TMPDIR:-/tmp}/flexipos-deploy-${SITE}.lock"
if ! mkdir "$lock_dir" 2>/dev/null; then
  lock_pid=$(cat "$lock_dir/pid" 2>/dev/null || true)
  if [[ "$lock_pid" =~ ^[0-9]+$ ]] && kill -0 "$lock_pid" 2>/dev/null; then
    echo "Another staging deployment is running (PID $lock_pid)" >&2
    exit 1
  fi
  rm -rf "$lock_dir"
  mkdir "$lock_dir"
fi
printf '%s\n' "$$" > "$lock_dir/pid"
trap 'rm -rf "$lock_dir"' EXIT

previous_sha=$(git -C "$app_dir" rev-parse HEAD)
git -C "$app_dir" fetch --quiet origin "$DEPLOY_REF"
target_sha=$(git -C "$app_dir" rev-parse FETCH_HEAD)
if [[ "$ALLOW_NON_FF" != 1 ]] && ! git -C "$app_dir" merge-base --is-ancestor "$previous_sha" "$target_sha"; then
  echo "Refusing non-fast-forward staging deployment; set ALLOW_NON_FF=1 explicitly" >&2
  exit 1
fi

SITE="$SITE" BENCH_PATH="$BENCH_PATH" bash "$BACKUP_SCRIPT"

maintenance_enabled=0
rollback() {
  local status=$?
  trap - ERR
  echo "Deployment failed; rolling the application back to $previous_sha" >&2
  git -C "$app_dir" reset --hard "$previous_sha"
  (cd "$BENCH_PATH" && bench setup requirements --python)
  (cd "$BENCH_PATH" && bench --site "$SITE" migrate)
  (cd "$BENCH_PATH" && bench build --app flexipos)
  (cd "$BENCH_PATH" && bench restart)
  if (( maintenance_enabled )); then
    (cd "$BENCH_PATH" && bench --site "$SITE" set-maintenance-mode off) || true
  fi
  exit "$status"
}
trap rollback ERR

(cd "$BENCH_PATH" && bench --site "$SITE" set-maintenance-mode on)
maintenance_enabled=1
git -C "$app_dir" reset --hard "$target_sha"
(cd "$BENCH_PATH" && bench setup requirements --python)
(cd "$BENCH_PATH" && bench --site "$SITE" migrate)
(cd "$BENCH_PATH" && bench build --app flexipos)
(cd "$BENCH_PATH" && bench restart)
(cd "$BENCH_PATH" && bench --site "$SITE" set-maintenance-mode off)
maintenance_enabled=0

curl --fail --silent --show-error --location \
  --retry 5 --retry-delay 3 --retry-connrefused "$HEALTHCHECK_URL" >/dev/null
trap - ERR
echo "Staging backend deployed at $target_sha"
