import frappe
from frappe import _
from frappe.model.document import Document


class FlexiPOSStockMovement(Document):
    """Immutable companion ledger for FlexiPOS simple stock counts."""

    def before_save(self):
        if not self.is_new():
            frappe.throw(_("Stock movements are immutable"))

    def on_trash(self):
        frappe.throw(_("Stock movements cannot be deleted"))

