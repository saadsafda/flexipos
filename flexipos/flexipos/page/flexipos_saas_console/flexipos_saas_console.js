frappe.pages["flexipos-saas-console"].on_page_load = (wrapper) => {
	const page = frappe.ui.make_app_page({
		parent: wrapper,
		title: __("FlexiPOS SaaS Console"),
		single_column: true,
	});
	wrapper.saas_console = new FlexiPOSSaaSConsole(page, wrapper);
};

frappe.pages["flexipos-saas-console"].on_page_show = (wrapper) => {
	wrapper.saas_console?.refresh();
};

class FlexiPOSSaaSConsole {
	constructor(page, wrapper) {
		this.page = page;
		this.wrapper = wrapper;
		this.tenants = [];
		this.filters = { search: "", status: "" };

		this.page.set_primary_action(__("Refresh"), () => this.refresh(), "refresh");
		this.page.add_menu_item(__("SaaS Settings"), () => {
			frappe.set_route("Form", "FlexiPOS SaaS Settings", "FlexiPOS SaaS Settings");
		});
		this.page.add_menu_item(__("Change default trial"), () => this.change_default_trial());
		this.make();
	}

	make() {
		this.root = $("<div class='flexipos-saas-console'></div>").appendTo(this.page.main);
		this.security = $(`
			<div class="saas-security-notice">
				<div>
					<strong>${__("Operator-only lifecycle controls")}</strong>
					<span>${__("Every change is checked on the server and written to the permanent activity trail.")}</span>
				</div>
			</div>
		`).appendTo(this.root);
		this.summary = $("<div class='saas-summary-grid'></div>").appendTo(this.root);

		const toolbar = $("<div class='saas-toolbar'></div>").appendTo(this.root);
		this.search = $(`
			<div class="saas-search">
				<input type="search" class="form-control" placeholder="${__("Search business or billing email")}">
			</div>
		`).appendTo(toolbar);
		this.status = $(`
			<select class="form-control saas-status-filter">
				<option value="">${__("All lifecycle states")}</option>
				<option value="Trialing">${__("Trialing")}</option>
				<option value="Active">${__("Active")}</option>
				<option value="Past Due">${__("Past Due")}</option>
				<option value="Suspended">${__("Suspended")}</option>
				<option value="Cancelled">${__("Cancelled")}</option>
				<option value="Archived">${__("Archived")}</option>
			</select>
		`).appendTo(toolbar);
		this.result_count = $("<span class='text-muted saas-result-count'></span>").appendTo(toolbar);

		this.search.find("input").on("input", frappe.utils.debounce((event) => {
			this.filters.search = event.target.value.trim().toLowerCase();
			this.render();
		}, 180));
		this.status.on("change", (event) => {
			this.filters.status = event.target.value;
			this.render();
		});

		this.content = $("<div class='saas-tenant-list'></div>").appendTo(this.root);
	}

	async refresh() {
		if (frappe.session.user !== "Administrator") {
			this.summary.empty();
			this.content.html(`
				<div class="saas-empty-state">
					<h4>${__("Administrator access required")}</h4>
					<p>${__("Cross-tenant billing and lifecycle data is restricted to the site Administrator.")}</p>
				</div>
			`);
			return;
		}
		this.page.set_indicator(__("Loading"), "orange");
		this.content.html(`<div class="saas-loading">${__("Loading tenants…")}</div>`);
		try {
			const response = await frappe.call({
				method: "flexipos.api.saas_list_tenants",
				args: { limit: 500, start: 0 },
			});
			this.tenants = response.message?.tenants || [];
			this.default_trial_days = response.message?.default_trial_days ?? 0;
			this.render();
			this.page.set_indicator(__("Live"), "green");
		} catch (error) {
			this.page.set_indicator(__("Unavailable"), "red");
			this.content.empty().append(
				$("<div class='saas-empty-state'></div>")
					.append($("<h4></h4>").text(__("Could not load tenant operations")))
					.append($("<p></p>").text(error.message || __("Please try again.")))
			);
		}
	}

	filtered_tenants() {
		return this.tenants.filter((tenant) => {
			const status_matches = !this.filters.status || tenant.status === this.filters.status;
			const haystack = [
				tenant.company,
				tenant.company_name,
				tenant.billing_email,
				tenant.business_type,
			]
				.filter(Boolean)
				.join(" ")
				.toLowerCase();
			return status_matches && (!this.filters.search || haystack.includes(this.filters.search));
		});
	}

	render() {
		this.render_summary();
		const tenants = this.filtered_tenants();
		this.result_count.text(__("{0} of {1} tenants", [tenants.length, this.tenants.length]));
		this.content.empty();
		if (!tenants.length) {
			this.content.append(`
				<div class="saas-empty-state">
					<h4>${__("No tenants match these filters")}</h4>
					<p>${__("Clear the search or select another lifecycle state.")}</p>
				</div>
			`);
			return;
		}

		const table = $(`
			<div class="saas-table-wrap">
				<table class="table saas-table">
					<thead>
						<tr>
							<th>${__("Business")}</th>
							<th>${__("Lifecycle")}</th>
							<th>${__("Trial / period")}</th>
							<th>${__("Plan")}</th>
							<th>${__("Billing contact")}</th>
							<th class="text-right">${__("Actions")}</th>
						</tr>
					</thead>
					<tbody></tbody>
				</table>
			</div>
		`).appendTo(this.content);
		const tbody = table.find("tbody");
		tenants.forEach((tenant) => tbody.append(this.tenant_row(tenant)));
	}

	render_summary() {
		const count = (status) => this.tenants.filter((tenant) => tenant.status === status).length;
		const cards = [
			[__("Total tenants"), this.tenants.length, "blue"],
			[__("Active"), count("Active"), "green"],
			[__("Trialing"), count("Trialing"), "orange"],
			[__("Needs attention"), count("Past Due") + count("Suspended"), "red"],
			[__("Default trial"), __("{0} days", [this.default_trial_days]), "gray"],
		];
		this.summary.empty();
		cards.forEach(([label, value, color]) => {
			const card = $("<div class='saas-summary-card'></div>").appendTo(this.summary);
			$("<span class='saas-summary-label'></span>").text(label).appendTo(card);
			$("<strong class='saas-summary-value'></strong>").text(value).appendTo(card);
			$("<i class='saas-summary-dot'></i>").addClass(`is-${color}`).appendTo(card);
		});
	}

	tenant_row(tenant) {
		const row = $("<tr></tr>");
		const business = $("<td></td>").appendTo(row);
		$("<button class='saas-business-link'></button>")
			.text(tenant.company_name || tenant.company)
			.on("click", () => frappe.set_route("Form", "Company", tenant.company))
			.appendTo(business);
		$("<small></small>")
			.text([tenant.business_type, tenant.company].filter(Boolean).join(" · "))
			.appendTo(business);

		const lifecycle = $("<td></td>").appendTo(row);
		$("<span class='saas-status-pill'></span>")
			.addClass(`is-${frappe.scrub(tenant.status || "unknown")}`)
			.text(tenant.status || __("Unknown"))
			.appendTo(lifecycle);
		if (tenant.payment_gateway_disabled) {
			$("<small></small>").text(__("Free access")).appendTo(lifecycle);
		}

		$("<td></td>")
			.append($("<span></span>").text(this.period_label(tenant)))
			.appendTo(row);
		$("<td></td>").text(tenant.plan || __("Not selected")).appendTo(row);
		$("<td></td>").text(tenant.billing_email || __("Not configured")).appendTo(row);

		const actions = $("<td class='text-right saas-row-actions'></td>").appendTo(row);
		$("<button class='btn btn-xs btn-default'></button>")
			.text(__("Extend trial"))
			.on("click", () => this.extend_trial(tenant))
			.appendTo(actions);
		$("<button class='btn btn-xs btn-default'></button>")
			.text(__("Lifecycle"))
			.on("click", () => this.change_lifecycle(tenant))
			.appendTo(actions);
		return row;
	}

	period_label(tenant) {
		const value = tenant.status === "Trialing"
			? tenant.trial_ends_on
			: tenant.current_period_end;
		if (!value) {
			return __("No end date");
		}
		return frappe.datetime.str_to_user(value);
	}

	change_default_trial() {
		const dialog = new frappe.ui.Dialog({
			title: __("Change default trial"),
			fields: [{
				fieldname: "days",
				fieldtype: "Int",
				label: __("Days for future tenants"),
				default: this.default_trial_days,
				reqd: 1,
			}],
			primary_action_label: __("Save"),
			primary_action: async ({ days }) => {
				if (days < 0 || days > 90) {
					frappe.msgprint(__("Default trial days must be between 0 and 90"));
					return;
				}
				await frappe.call({
					method: "flexipos.api.saas_set_default_trial_days",
					args: { days },
					freeze: true,
				});
				dialog.hide();
				frappe.show_alert({ message: __("Default trial updated"), indicator: "green" });
				await this.refresh();
			},
		});
		dialog.show();
	}

	extend_trial(tenant) {
		const dialog = new frappe.ui.Dialog({
			title: __("Extend trial for {0}", [tenant.company_name || tenant.company]),
			fields: [{
				fieldname: "days",
				fieldtype: "Int",
				label: __("Additional days"),
				default: this.default_trial_days || 30,
				reqd: 1,
			}],
			primary_action_label: __("Extend trial"),
			primary_action: async ({ days }) => {
				if (days < 1 || days > 365) {
					frappe.msgprint(__("Trial extension must be between 1 and 365 days"));
					return;
				}
				await frappe.call({
					method: "flexipos.api.saas_extend_trial",
					args: { company: tenant.company, days },
					freeze: true,
				});
				dialog.hide();
				frappe.show_alert({ message: __("Trial extended"), indicator: "green" });
				await this.refresh();
			},
		});
		dialog.show();
	}

	change_lifecycle(tenant) {
		const dialog = new frappe.ui.Dialog({
			title: __("Change lifecycle for {0}", [tenant.company_name || tenant.company]),
			fields: [
				{
					fieldname: "status",
					fieldtype: "Select",
					label: __("Lifecycle state"),
					options: ["Suspended", "Cancelled", "Archived", "Active"],
					reqd: 1,
				},
				{
					fieldname: "current_period_end",
					fieldtype: "Datetime",
					label: __("Paid period ends"),
					depends_on: "eval:doc.status === 'Active'",
					mandatory_depends_on: "eval:doc.status === 'Active'",
				},
				{
					fieldname: "reason",
					fieldtype: "Small Text",
					label: __("Operator reason"),
					reqd: 1,
				},
			],
			primary_action_label: __("Apply lifecycle change"),
			primary_action: async (values) => {
				const warning = __("Set {0} to {1}?", [
					tenant.company_name || tenant.company,
					values.status,
				]);
				frappe.confirm(warning, async () => {
					await frappe.call({
						method: "flexipos.api.saas_set_tenant_status",
						args: {
							company: tenant.company,
							status: values.status,
							current_period_end: values.current_period_end || null,
							reason: values.reason,
						},
						freeze: true,
					});
					dialog.hide();
					frappe.show_alert({ message: __("Lifecycle updated"), indicator: "green" });
					await this.refresh();
				});
			},
		});
		dialog.show();
	}
}
