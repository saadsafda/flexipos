import frappe


def execute():
	"""Options used to carry a free-text label; each now links a
	FlexiPOS Modifier master. Backfill a master per distinct
	(business, label) and point the existing option rows at it."""
	rows = frappe.db.sql(
		"""
		SELECT opt.name, opt.label, opt.price, grp.flexipos_company AS company
		FROM `tabFlexiPOS Modifier Option` opt
		LEFT JOIN `tabFlexiPOS Modifier Group` grp ON grp.name = opt.parent
		WHERE IFNULL(opt.modifier, '') = '' AND IFNULL(opt.label, '') != ''
		""",
		as_dict=True,
	)
	masters = {}
	for row in rows:
		key = (row.company, row.label)
		if key not in masters:
			existing = frappe.db.get_value(
				"FlexiPOS Modifier",
				{"modifier_name": row.label, "flexipos_company": row.company},
			)
			if not existing:
				modifier = frappe.new_doc("FlexiPOS Modifier")
				modifier.modifier_name = row.label
				modifier.flexipos_company = row.company
				modifier.price = row.price
				modifier.insert(ignore_permissions=True)
				existing = modifier.name
			masters[key] = existing
		frappe.db.set_value(
			"FlexiPOS Modifier Option",
			row.name,
			"modifier",
			masters[key],
			update_modified=False,
		)
