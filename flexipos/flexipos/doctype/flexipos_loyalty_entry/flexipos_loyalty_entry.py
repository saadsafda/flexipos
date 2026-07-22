import frappe
from frappe import _
from frappe.model.document import Document


class FlexiPOSLoyaltyEntry(Document):
    def before_save(self):
        if not self.is_new():
            frappe.throw(_("Loyalty entries are immutable"))

    def on_trash(self):
        frappe.throw(_("Loyalty entries cannot be deleted"))
