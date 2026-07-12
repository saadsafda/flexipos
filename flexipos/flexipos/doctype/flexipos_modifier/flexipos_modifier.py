# Copyright (c) 2026, FlexiPOS and contributors
# For license information, please see license.txt

import frappe
from frappe import _
from frappe.model.document import Document


class FlexiPOSModifier(Document):
	def validate(self):
		duplicate = frappe.db.exists(
			"FlexiPOS Modifier",
			{
				"modifier_name": self.modifier_name,
				"flexipos_company": self.flexipos_company,
				"name": ("!=", self.name),
			},
		)
		if duplicate:
			frappe.throw(
				_("Modifier {0} already exists for this business").format(self.modifier_name)
			)
