import frappe
from frappe import _
from frappe.model.document import Document
from frappe.utils import cint


class FlexiPOSPromotion(Document):
    def validate(self):
        self.code = (self.code or "").strip().upper()
        if not self.code or len(self.code) > 40:
            frappe.throw(_("Promotion code is required and must be 40 characters or fewer"))
        duplicate = frappe.db.exists(
            "FlexiPOS Promotion",
            {"company": self.company, "code": self.code, "name": ("!=", self.name)},
        )
        if duplicate:
            frappe.throw(_("Promotion code already exists for this business"))
        if self.discount_type == "Percentage" and not 0 < cint(self.percentage_basis_points) <= 10000:
            frappe.throw(_("Percentage must be between 0 and 100 percent"))
        if self.discount_type == "Fixed" and cint(self.fixed_amount_minor) <= 0:
            frappe.throw(_("Fixed discount must be greater than zero"))
        if cint(self.minimum_spend_minor) < 0 or cint(self.maximum_discount_minor) < 0:
            frappe.throw(_("Promotion amounts cannot be negative"))
        if cint(self.usage_limit) < 0 or cint(self.used_count) < 0:
            frappe.throw(_("Promotion usage values cannot be negative"))
        if cint(self.usage_limit) and cint(self.used_count) > cint(self.usage_limit):
            frappe.throw(_("Usage limit cannot be below the used count"))
        if self.starts_at and self.ends_at and self.starts_at > self.ends_at:
            frappe.throw(_("Promotion end must be after its start"))
