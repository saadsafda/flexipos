"""Scheduled SaaS lifecycle jobs for FlexiPOS.

The daily job only changes tenant lifecycle metadata and anonymises accounts
that passed their explicit retention window. Sales and tax documents are
never silently deleted; operators can apply their local legal retention policy
before removing immutable financial records.
"""

import hashlib

import frappe
from frappe.utils import cint, escape_html, get_datetime, now_datetime

from flexipos.api import (
    BILLING_CUSTOMER_FIELD,
    BILLING_EMAIL_FIELD,
    BILLING_EVENT_FIELD,
    CURRENT_PERIOD_END_FIELD,
    DELETION_REQUESTED_FIELD,
    DEVICE_ID_FIELD,
    PIN_HASH_FIELD,
    RETENTION_UNTIL_FIELD,
    SUBSCRIPTION_STATUS_FIELD,
    TRIAL_ENDS_FIELD,
    _get_saas_settings,
    _payment_gateway_disabled,
)

BILLING_NOTICE_DOCTYPE = "FlexiPOS Billing Notice"
DEFAULT_REMINDER_DAYS = {1, 3, 7, 14}


def run_subscription_lifecycle():
    """Expire trials/periods and process deletion requests."""
    _expire_subscriptions()
    _send_failed_payment_reminders()
    _purge_expired_tenants()


def _expire_subscriptions():
    if _payment_gateway_disabled():
        return
    now = now_datetime()
    for row in frappe.get_all(
        "Company",
        fields=["name", SUBSCRIPTION_STATUS_FIELD, TRIAL_ENDS_FIELD, CURRENT_PERIOD_END_FIELD],
        limit_page_length=0,
    ):
        status = row.get(SUBSCRIPTION_STATUS_FIELD)
        if status == "Trialing" and row.get(TRIAL_ENDS_FIELD) and get_datetime(row[TRIAL_ENDS_FIELD]) <= now:
            frappe.db.set_value("Company", row.name, SUBSCRIPTION_STATUS_FIELD, "Past Due", update_modified=False)
            queue_billing_notice(
                row.name,
                "trial_expired",
                event_id=f"trial-expired:{get_datetime(row[TRIAL_ENDS_FIELD]).date()}",
            )
        elif status == "Active" and row.get(CURRENT_PERIOD_END_FIELD) and get_datetime(row[CURRENT_PERIOD_END_FIELD]) <= now:
            frappe.db.set_value("Company", row.name, SUBSCRIPTION_STATUS_FIELD, "Past Due", update_modified=False)
            queue_billing_notice(
                row.name,
                "payment_failed",
                event_id=f"period-expired:{get_datetime(row[CURRENT_PERIOD_END_FIELD]).date()}",
            )


def _send_failed_payment_reminders():
    if _payment_gateway_disabled():
        return
    today = now_datetime().date()
    for row in frappe.get_all(
        "Company",
        filters={SUBSCRIPTION_STATUS_FIELD: "Past Due"},
        fields=[
            "name",
            TRIAL_ENDS_FIELD,
            CURRENT_PERIOD_END_FIELD,
        ],
        limit_page_length=0,
    ):
        ended_at = row.get(CURRENT_PERIOD_END_FIELD) or row.get(TRIAL_ENDS_FIELD)
        if not ended_at:
            continue
        days_overdue = (today - get_datetime(ended_at).date()).days
        if days_overdue not in DEFAULT_REMINDER_DAYS:
            continue
        queue_billing_notice(
            row.name,
            "payment_reminder",
            event_id=f"overdue-day-{days_overdue}:{today}",
        )


def queue_billing_notice(company, kind, event_id=None):
    """Create and enqueue one notice; duplicate event retries are harmless."""
    if _payment_gateway_disabled():
        return None
    if not frappe.db.exists("DocType", BILLING_NOTICE_DOCTYPE):
        return None
    settings = _get_saas_settings()
    if not cint(getattr(settings, "billing_email_enabled", 1)):
        return None
    recipient = (
        frappe.db.get_value("Company", company, BILLING_EMAIL_FIELD) or ""
    ).strip().lower()
    if not recipient:
        return None
    raw_key = f"{company}\0{kind}\0{event_id or ''}"
    notice_key = hashlib.sha256(raw_key.encode()).hexdigest()
    if frappe.db.exists(BILLING_NOTICE_DOCTYPE, notice_key):
        return notice_key
    frappe.get_doc(
        {
            "doctype": BILLING_NOTICE_DOCTYPE,
            "notice_key": notice_key,
            "company": company,
            "kind": str(kind)[:80],
            "recipient": recipient,
            "status": "Pending",
            "event_id": str(event_id or "")[:140],
            "scheduled_for": now_datetime(),
            "attempts": 0,
        }
    ).insert(ignore_permissions=True)
    frappe.enqueue(
        "flexipos.tasks.send_billing_notice",
        notice_key=notice_key,
        enqueue_after_commit=True,
    )
    return notice_key


def send_billing_notice(notice_key):
    """Deliver a queued notice and retain its immutable delivery outcome."""
    notice = frappe.get_doc(BILLING_NOTICE_DOCTYPE, notice_key)
    if notice.status in ("Sent", "Skipped"):
        return {"notice_key": notice_key, "status": notice.status}
    company_name = frappe.db.get_value(
        "Company", notice.company, "company_name"
    ) or notice.company
    subject, intro = _billing_notice_copy(notice.kind, company_name)
    settings = _get_saas_settings()
    support_email = (
        getattr(settings, "billing_support_email", None)
        or frappe.get_system_settings("email_footer_address")
        or ""
    )
    billing_url = (
        getattr(settings, "billing_portal_url", None)
        or frappe.utils.get_url()
    )
    message = (
        f"<p>{escape_html(intro)}</p>"
        f"<p><a href='{escape_html(billing_url)}'>"
        f"{escape_html('Review billing and subscription')}</a></p>"
    )
    if support_email:
        message += (
            f"<p>{escape_html('Need help? Contact ')}"
            f"{escape_html(support_email)}</p>"
        )
    attempts = cint(notice.attempts) + 1
    delivery_status = "Failed"
    try:
        frappe.sendmail(
            recipients=[notice.recipient],
            subject=subject,
            message=message,
            reference_doctype=BILLING_NOTICE_DOCTYPE,
            reference_name=notice.name,
            now=True,
        )
        notice.db_set(
            {
                "status": "Sent",
                "sent_at": now_datetime(),
                "attempts": attempts,
                "last_error": "",
            },
            update_modified=False,
        )
        delivery_status = "Sent"
    except Exception as exc:
        notice.db_set(
            {
                "status": "Failed",
                "attempts": attempts,
                "last_error": str(exc)[:500],
            },
            update_modified=False,
        )
        frappe.log_error(
            frappe.get_traceback(), f"FlexiPOS billing email failed: {notice_key}"
        )
    return {"notice_key": notice_key, "status": delivery_status}


def _billing_notice_copy(kind, company_name):
    name = str(company_name)
    if kind == "payment_succeeded":
        return (
            f"Payment confirmed for {name}",
            f"Your Sprout subscription payment for {name} was confirmed.",
        )
    if kind == "subscription_cancelled":
        return (
            f"Subscription cancelled for {name}",
            f"The Sprout subscription for {name} has been cancelled.",
        )
    if kind == "trial_expired":
        return (
            f"Free trial ended for {name}",
            f"The free trial for {name} has ended. Choose a plan to restore online services.",
        )
    return (
        f"Payment action needed for {name}",
        f"We could not confirm the latest subscription payment for {name}. Please review billing to avoid interrupted online services.",
    )


def _purge_expired_tenants():
    today = now_datetime().date()
    for row in frappe.get_all(
        "Company",
        filters={SUBSCRIPTION_STATUS_FIELD: ("in", ["Cancelled", "Suspended"])},
        fields=["name", RETENTION_UNTIL_FIELD, DELETION_REQUESTED_FIELD],
        limit_page_length=0,
    ):
        retention = row.get(RETENTION_UNTIL_FIELD)
        if not retention or get_datetime(retention).date() > today:
            continue
        _anonymise_tenant(row.name)


def _anonymise_tenant(company):
    users = frappe.get_all(
        "User Permission",
        filters={"allow": "Company", "for_value": company},
        pluck="user",
    )
    for user in users:
        # Keep the User name for audit references, but remove login/device
        # PII and disable access. A deterministic suffix avoids unique-email
        # collisions while making the account unrecoverable.
        suffix = hashlib.sha256(f"{company}:{user}".encode()).hexdigest()[:16]
        frappe.db.set_value(
            "User",
            user,
            {
                "enabled": 0,
                "first_name": "Deleted user",
                "middle_name": "",
                "last_name": "",
                "mobile_no": "",
                PIN_HASH_FIELD: "",
                DEVICE_ID_FIELD: "",
                "email": f"deleted+{suffix}@invalid.flexipos",
            },
            update_modified=False,
        )
    frappe.db.set_value(
        "Company",
        company,
        {
            SUBSCRIPTION_STATUS_FIELD: "Archived",
            "flexipos_phone": "",
            BILLING_EMAIL_FIELD: "",
            BILLING_CUSTOMER_FIELD: "",
            BILLING_EVENT_FIELD: "",
        },
        update_modified=False,
    )
