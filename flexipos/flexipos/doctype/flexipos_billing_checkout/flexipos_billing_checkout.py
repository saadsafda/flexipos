import frappe
from frappe.model.document import Document


class FlexiPOSBillingCheckout(Document):
    def validate(self):
        if self.status not in {"Pending", "Completed", "Cancelled", "Failed"}:
            frappe.throw("Invalid billing checkout status")
