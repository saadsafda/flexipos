from urllib.parse import urlparse

import frappe
from frappe import _
from frappe.model.document import Document


class FlexiPOSBillingInvoice(Document):
    def validate(self):
        for fieldname in ("hosted_url", "pdf_url"):
            value = (self.get(fieldname) or "").strip()
            parsed = urlparse(value)
            if value and (parsed.scheme != "https" or not parsed.netloc):
                frappe.throw(_("Billing invoice links must use HTTPS"))

    def on_trash(self):
        if not frappe.flags.in_uninstall:
            frappe.throw(_("Billing invoice history is permanent"))
