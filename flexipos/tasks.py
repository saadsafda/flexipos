"""Scheduled SaaS lifecycle jobs for FlexiPOS.

The daily job only changes tenant lifecycle metadata and anonymises accounts
that passed their explicit retention window. Sales and tax documents are
never silently deleted; operators can apply their local legal retention policy
before removing immutable financial records.
"""

import hashlib

import frappe
from frappe.utils import get_datetime, now_datetime

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
    _payment_gateway_disabled,
)


def run_subscription_lifecycle():
    """Expire trials/periods and process deletion requests."""
    _expire_subscriptions()
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
        elif status == "Active" and row.get(CURRENT_PERIOD_END_FIELD) and get_datetime(row[CURRENT_PERIOD_END_FIELD]) <= now:
            frappe.db.set_value("Company", row.name, SUBSCRIPTION_STATUS_FIELD, "Past Due", update_modified=False)


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
