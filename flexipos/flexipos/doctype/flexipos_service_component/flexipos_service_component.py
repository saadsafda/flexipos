import frappe
from frappe import _
from frappe.model.document import Document
from frappe.utils import now_datetime


class FlexiPOSServiceComponent(Document):
    def validate(self):
        self.component_key = (self.component_key or "").strip().lower()[:140]
        self.label = (self.label or "").strip()[:140]
        self.message = (self.message or "").strip()[:500]
        self.updated_at = now_datetime()
        if not self.component_key or not self.label:
            frappe.throw(_("Component key and label are required"))

