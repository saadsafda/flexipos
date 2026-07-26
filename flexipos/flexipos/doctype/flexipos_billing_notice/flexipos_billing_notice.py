import frappe
from frappe import _
from frappe.model.document import Document


class FlexiPOSBillingNotice(Document):
    def on_trash(self):
        if not frappe.flags.in_uninstall:
            frappe.throw(_("Billing notice history is permanent"))
