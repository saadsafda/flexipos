from urllib.parse import urlparse

import frappe
from frappe import _
from frappe.model.document import Document
from frappe.utils import cint, validate_email_address


class FlexiPOSSaaSSettings(Document):
    """Site-wide SaaS configuration.

    This is a singleton owned by the SaaS operator, never by an individual
    tenant. Password fields are encrypted by Frappe and are never returned by
    FlexiPOS tenant APIs.
    """

    def validate(self):
        self.disable_payment_gateway = cint(self.disable_payment_gateway)
        self.billing_provider = (self.billing_provider or "Safepay").strip()
        self.default_plan = (self.default_plan or "monthly").strip()[:80]
        self.default_trial_days = cint(self.default_trial_days)
        self.deletion_retention_days = cint(self.deletion_retention_days)

        if self.disable_payment_gateway:
            # Keep the persisted configuration unambiguous. Provider secrets
            # are retained so billing can be re-enabled later, but no checkout
            # or payment-method requirement remains active in free-access mode.
            self.billing_enabled = 0
            self.require_payment_method_on_signup = 0

        if not 0 <= self.default_trial_days <= 90:
            frappe.throw(_("Default trial days must be between 0 and 90"))
        if not 1 <= self.deletion_retention_days <= 3650:
            frappe.throw(_("Deletion retention days must be between 1 and 3650"))

        if self.checkout_url:
            parsed = urlparse(self.checkout_url.strip())
            if parsed.scheme not in ({"http", "https"} if self.sandbox_mode else {"https"}):
                frappe.throw(_("Production checkout URL must use HTTPS"))
        if self.billing_portal_url:
            parsed = urlparse(self.billing_portal_url.strip())
            if parsed.scheme != "https" or not parsed.netloc:
                frappe.throw(_("Customer billing portal URL must use HTTPS"))
        if self.billing_support_email:
            validate_email_address(self.billing_support_email, throw=True)
        for fieldname in ("terms_url", "privacy_url", "retention_policy_url"):
            value = (self.get(fieldname) or "").strip()
            parsed = urlparse(value)
            if value and (parsed.scheme != "https" or not parsed.netloc):
                frappe.throw(
                    _("{0} must use a valid HTTPS URL").format(
                        self.meta.get_label(fieldname)
                    )
                )
        if self.legal_review_status == "Approved" and not (
            self.legal_reviewer and self.legal_reviewed_on
        ):
            frappe.throw(
                _("Approved legal review requires a reviewer and review date")
            )
        if self.tax_review_status == "Approved" and not (
            self.tax_reviewer
            and self.tax_reviewed_on
            and (self.tax_jurisdictions or "").strip()
        ):
            frappe.throw(
                _(
                    "Approved tax review requires a reviewer, review date and jurisdictions"
                )
            )

        if (
            not self.disable_payment_gateway
            and self.billing_enabled
            and self.billing_provider != "Manual"
        ):
            if not self.public_api_key:
                frappe.throw(_("Public API key is required when billing is enabled"))
            if not self.get_password("secret_api_key", raise_exception=False):
                frappe.throw(_("Secret API key is required when billing is enabled"))
            if not self.get_password("webhook_secret", raise_exception=False):
                frappe.throw(_("Webhook secret is required when billing is enabled"))

    def on_update(self):
        frappe.clear_cache(doctype=self.doctype)
