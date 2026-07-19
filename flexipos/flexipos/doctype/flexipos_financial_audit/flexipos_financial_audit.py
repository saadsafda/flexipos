import frappe
from frappe import _
from frappe.model.document import Document


class FlexiPOSFinancialAudit(Document):
    """Append-only, hash-chained evidence for financially sensitive events."""

    def before_save(self):
        if not self.is_new():
            frappe.throw(_("Financial audit events are immutable"))

    def on_trash(self):
        frappe.throw(_("Financial audit events cannot be deleted"))

