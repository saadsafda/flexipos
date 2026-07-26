frappe.ui.form.on("FlexiPOS SaaS Settings", {
	refresh(frm) {
		if (frappe.session.user !== "Administrator") {
			return;
		}
		frm.add_custom_button(__("Open SaaS Console"), () => {
			frappe.set_route("flexipos-saas-console");
		});
	},
});
