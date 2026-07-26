from urllib.parse import urlparse

import frappe
from frappe import _
from frappe.model.document import Document
from frappe.utils import cint


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
