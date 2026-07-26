import frappe
from frappe import _
from frappe.model.document import Document


class FlexiPOSPolicyAcceptance(Document):
    def on_trash(self):
        if not frappe.flags.in_uninstall:
            frappe.throw(_("Policy acceptance history is permanent"))

