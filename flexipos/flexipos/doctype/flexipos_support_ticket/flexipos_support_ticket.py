import frappe
from frappe import _
from frappe.model.document import Document


class FlexiPOSSupportTicket(Document):
    def validate(self):
        self.subject = (self.subject or "").strip()[:140]
        self.description = (self.description or "").strip()[:4000]
        if not self.subject:
            frappe.throw(_("Support ticket subject is required"))
        if not self.description:
            frappe.throw(_("Support ticket description is required"))

