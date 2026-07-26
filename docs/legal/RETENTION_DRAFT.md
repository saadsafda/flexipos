# Sprout Data Retention Policy — draft

Effective date: [DATE]  
Owner: [ROLE]  
Review cadence: [CADENCE]

| Data class | Default retention | Trigger | Disposal |
| --- | --- | --- | --- |
| Local unsynced POS records | Until acknowledged by server and operationally safe to remove | Successful sync | Controlled local cleanup |
| Financial/tax records | [JURISDICTION-SPECIFIC PERIOD] | Transaction date | Approved deletion/anonymisation |
| Permanent financial audit trail | [LEGAL PERIOD] | Event date | Restricted, reviewed process |
| Account and business profile | Subscription life plus deletion grace period | Closure/deletion request | Anonymisation |
| Billing invoice metadata | [LEGAL/ACCOUNTING PERIOD] | Invoice date | Restricted deletion process |
| Billing email delivery log | [PERIOD] | Delivery attempt | Scheduled deletion/anonymisation |
| Support tickets | [PERIOD] | Ticket closure | Scheduled deletion/anonymisation |
| Security/OTP data | Shortest operational period | Expiry/use | Automatic deletion |
| Aggregate operational metrics | [PERIOD] | Collection date | Aggregation/deletion |
| Backups | [PERIOD] | Backup creation | Rotation and expiry |

Deletion requests use the grace period configured in FlexiPOS SaaS Settings.
The production schedule must reflect tax, accounting, employment, consumer,
privacy, and litigation-hold obligations in every launch jurisdiction.

