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
# SaaS billing, tenant lifecycle and privacy

Every newly created business starts with a seven-day `Trialing` subscription.
No card number, CVV, or PAN is accepted or persisted by FlexiPOS. The app
stores only an opaque payment-provider customer token and provider name.

The billing API is provider-neutral. In Pakistan, Safepay is a practical first
choice when its merchant account is approved because it supports PKR recurring
plans and hosted Checkout; configure a PSP such as PayFast if its merchant
account supports the plan/recurring flow you need;
manual bank settlement, Easypaisa/JazzCash, or another local gateway can use
the same signed webhook. Do not treat a gateway as the source of truth until
its webhook is verified.

All site-wide billing configuration is managed in the singleton
**FlexiPOS SaaS Settings** DocType. Only users with the System Manager role can
read or update it. Provider secret keys and the webhook secret use Frappe
`Password` fields and are encrypted at rest; they are never returned to tenant
or Flutter APIs.

Configure the provider, sandbox mode, public API key, secret API key, webhook
secret, hosted checkout URL, provider plan IDs, trial length, card/payment
method requirement, deletion retention, and legal links in that one document.
Open it from the Frappe Desk search by entering `FlexiPOS SaaS Settings`.
Do not grant System Manager to tenant staff merely so they can manage their
own subscription; this document controls every company on the site.

Safepay is the preferred first provider for Pakistan because its hosted
Checkout supports PKR recurring plans, trial periods, and vaulted payment
instruments. Keep PayFast/Raast/wallets as optional invoice or manual-renewal
rails unless your merchant agreement explicitly enables recurring tokenized
charges. Enable **Require Card / Payment Method on Signup** only after the
Safepay sandbox checkout and webhook adapter are live:

```sh
bench --site <site> migrate
```

When the signup payment-method setting is enabled, new and existing tenants without a
provider token are routed to hosted billing before operational screens. The
provider captures the card and returns an opaque instrument/customer token;
FlexiPOS never receives PAN or CVV. Leave the flag disabled until production
merchant credentials and the hosted checkout URL are configured.

The client flow is:

1. Call `get_subscription_status` after login. During trial, show the exact
   trial end timestamp and a billing CTA.
2. Collect billing details in the provider-hosted checkout (never in Flutter)
   and call `create_billing_checkout` with `provider`, `plan`, optional opaque
   `customer_token`, and `privacy_consent=true`.
3. The gateway sends `billing_webhook` with `event_id`, `status`, and a
   canonical `payload_json` signed using HMAC-SHA512 for Safepay (HMAC-SHA256
   for generic adapters). Duplicate event IDs are idempotent. An `Active`
   event must include a future `current_period_end`.
4. The daily scheduler moves expired trials/periods to `Past Due`. All tenant
   business endpoints enforce lifecycle status server-side; `Administrator`
   remains available to repair billing.

Supported account states are `Trialing`, `Active`, `Past Due`, `Suspended`,
`Cancelled`, and `Archived`. Operators can use `admin_set_subscription` for
verified manual settlements and `cancel_subscription` when a plan is ended.

Privacy controls are tenant-admin-only. `request_data_export` returns company,
user, and record-count data but excludes payment tokens. `request_account_deletion`
requires the exact company name and schedules a 30-day recovery/legal-retention
window. `cancel_data_deletion` restores an account during that window. The
daily lifecycle job then disables and anonymises tenant users, clears billing
identifiers, and marks the tenant `Archived`; financial documents are retained
for the site's legal retention policy and are not silently destroyed.

## SaaS operator controls

Only the Frappe `Administrator` can call these cross-tenant methods. Each
change writes an Activity Log entry without payment credentials:

- `saas_list_tenants` lists subscription, trial, provider and deletion state.
- `saas_set_default_trial_days(days)` changes the trial for future companies
  from 0 to 90 days. The initial default is 7 days.
- `saas_extend_trial(company=..., days=...)` adds time to one company.
- `saas_extend_trial(all_companies=1, days=...)` adds time to all eligible
  companies, excluding archived or deletion-pending tenants.
- `saas_set_tenant_status(company, status, current_period_end, reason)`
  suspends, reactivates, cancels or archives a company.

Example bench calls:

```sh
bench --site <site> execute flexipos.api.saas_extend_trial \
  --kwargs '{"company":"Example Company","days":14}'
bench --site <site> execute flexipos.api.saas_extend_trial \
  --kwargs '{"all_companies":1,"days":3}'
bench --site <site> execute flexipos.api.saas_set_default_trial_days \
  --kwargs '{"days":7}'
bench --site <site> execute flexipos.api.saas_set_tenant_status \
  --kwargs '{"company":"Example Company","status":"Suspended","reason":"Chargeback review"}'
```

Billing webhook receipts are recorded in `FlexiPOS Billing Event` with a
unique provider event ID and payload hash, so older replayed events cannot be
accepted merely because a newer event arrived in between.
