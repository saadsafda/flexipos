# Backend operations

## Continuous integration

`.github/workflows/backend-ci.yml` creates a clean Frappe v16 + ERPNext v16
site on MariaDB, installs FlexiPOS, runs Ruff and then the complete app test
suite. Protect `version-16` and require `Lint and tenant-isolation tests` before
merging.

## Crash monitoring

Frappe v16 already initializes Sentry for web requests and background workers.
Add the values from `deploy/systemd/sentry.env.example` to the environment of
every Frappe web and worker service, then restart the bench processes. Use a
dedicated staging Sentry project first and verify web-request and worker test
events before configuring production paging.

`ENABLE_SENTRY_DB_MONITORING` stays disabled because recorded SQL parameters
can contain tenant or customer data. Keep separate projects and alert routing
for staging and production.

## Encrypted off-site backups

The backup contains the compressed database, public files, private files, and
site configuration. `scripts/backup_site.sh` validates each file, generates
SHA-256 checksums, encrypts every artifact with `age`, uploads through `rclone`,
and applies local/off-site retention. A failed command returns a non-zero exit
status, which systemd records as a failed unit.

1. Generate an offline recovery identity on a secure administrator machine:

   ```sh
   age-keygen -o flexipos-backup-identity.txt
   age-keygen -y flexipos-backup-identity.txt
   ```

   Store the private identity outside the application server and password
   manager access under an audited break-glass process. Only the printed public
   recipient is installed on the server.

2. Configure an object-storage remote for the `frappe` service user with
   `rclone config`. Grant write/list/delete access only to the backup prefix and
   enable bucket versioning or object lock at the provider.

3. Copy `deploy/systemd/backup.env.example` to `/etc/flexipos/backup.env`, make
   it root-owned mode `0600`, and replace all example values. Copy the service
   and timer into `/etc/systemd/system/`. Adjust `/home/frappe/frappe-bench` and
   the service account if the bench uses different paths.

4. Enable and test the timer for a site:

   ```sh
   sudo systemctl daemon-reload
   sudo systemctl enable --now flexipos-backup@staging.example.com.timer
   sudo systemctl start flexipos-backup@staging.example.com.service
   sudo journalctl -u flexipos-backup@staging.example.com.service
   systemctl list-timers 'flexipos-backup@*'
   ```

5. Download one backup from object storage and verify it on a separate machine:

   ```sh
   scripts/verify_backup.sh /secure/download/20260713T021500Z \
     /secure/offline/flexipos-backup-identity.txt
   ```

Run a quarterly restore drill on a disposable isolated site. Decrypt the five
artifacts into a temporary mode-`0700` directory, verify them, then restore:

```sh
bench --site restore-drill.example.com restore database.sql.gz \
  --with-public-files public-files.tgz \
  --with-private-files private-files.tgz
bench --site restore-drill.example.com migrate
```

Use the backed-up `site-config.json` to recover encryption settings only after
reviewing its database credentials and hostname for the restore target. Record
restore time, row-count checks, sampled invoice totals, and attachment checks.
Backups are not considered healthy until this drill succeeds. Monitor failed
systemd units and object-storage age/size from an external alerting system.

## Protected staging deployment

Create a GitHub environment named `staging`, require an administrator reviewer,
and restrict deployments to `version-16`. Configure:

| Type | Name |
| --- | --- |
| Variable | `STAGING_BACKEND_URL` |
| Variable | `STAGING_BENCH_PATH` |
| Variable | `STAGING_SITE` |
| Variable | `STAGING_SSH_HOST` |
| Variable | `STAGING_SSH_PORT` (optional) |
| Variable | `STAGING_SSH_USER` |
| Secret | `STAGING_SSH_KEY` |
| Secret | `STAGING_SSH_KNOWN_HOSTS` |

The staging server itself must have `/etc/flexipos/backup.env` (or equivalent
exported variables), `age`, `rclone`, and `bench` available to the deployment
user. Grant that user the minimum permissions needed to manage this bench.

Run **Deploy backend staging** manually. The script refuses a dirty checkout or
a non-fast-forward revision, takes and uploads a verified backup, enables
maintenance mode, installs Python requirements, migrates, builds, restarts, and
checks `/api/method/ping` over HTTPS. Application files roll back automatically
on an error. Database migrations are not automatically reversible; if a failed
migration changed data incompatibly, use the verified pre-deployment backup and
the restore procedure above.
