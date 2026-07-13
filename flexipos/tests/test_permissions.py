import ast
import json
from pathlib import Path
from typing import ClassVar
from unittest.mock import MagicMock, patch
from uuid import uuid4

import frappe
from frappe.tests.utils import FrappeTestCase

from flexipos import api


class TestScreenPermissionGuards(FrappeTestCase):
    def setUp(self):
        self.previous_user = frappe.session.user

    def tearDown(self):
        frappe.set_user(self.previous_user)

    def test_allows_a_granted_permission(self):
        frappe.set_user("Administrator")
        with patch.object(
            api, "_screen_permissions_for_user", return_value=["inventory"]
        ):
            api._require_screen_access("inventory")

    def test_rejects_a_missing_permission(self):
        frappe.set_user("Administrator")
        with patch.object(
            api, "_screen_permissions_for_user", return_value=["quick_sale"]
        ):
            with self.assertRaises(frappe.PermissionError):
                api._require_screen_access("inventory")

    def test_any_permission_accepts_one_match(self):
        frappe.set_user("Administrator")
        with patch.object(
            api, "_screen_permissions_for_user", return_value=["inventory"]
        ):
            api._require_any_screen_access("quick_sale", "inventory")

    def test_rejects_guest_even_if_permissions_are_mocked(self):
        frappe.set_user("Guest")
        with patch.object(
            api, "_screen_permissions_for_user", return_value=["inventory"]
        ):
            with self.assertRaises(frappe.AuthenticationError):
                api._require_screen_access("inventory")

    def test_missing_role_fails_closed_for_non_owner(self):
        with patch.object(frappe.db, "get_value", side_effect=[None, None]):
            self.assertEqual(api._effective_role("staff@example.com"), "Staff")

    def test_missing_role_preserves_legacy_company_owner(self):
        with patch.object(
            frappe.db,
            "get_value",
            side_effect=[None, "Example Company", "owner@example.com"],
        ):
            self.assertEqual(api._effective_role("owner@example.com"), "Admin")

    def test_linked_user_cannot_create_another_business(self):
        frappe.set_user("Administrator")
        with patch.object(frappe.db, "exists", return_value=True):
            with self.assertRaises(frappe.PermissionError):
                api._require_business_setup_access()

    def test_unlinked_authenticated_user_can_start_business_setup(self):
        frappe.set_user("Administrator")
        with patch.object(frappe.db, "exists", return_value=False):
            api._require_business_setup_access()


class TestTenantOwnership(FrappeTestCase):
    def setUp(self):
        self.previous_user = frappe.session.user
        frappe.set_user("Administrator")

    def tearDown(self):
        frappe.set_user(self.previous_user)

    def test_document_owned_by_company_is_allowed(self):
        with patch.object(frappe.db, "get_value", return_value="Company A"):
            result = api._require_document_company(
                "Item",
                "ITEM-1",
                "Company A",
                company_field="flexipos_company",
            )
        self.assertEqual(result, "ITEM-1")

    def test_cross_company_document_is_rejected(self):
        with patch.object(frappe.db, "get_value", return_value="Company B"):
            with self.assertRaises(frappe.PermissionError):
                api._require_document_company(
                    "Item",
                    "ITEM-1",
                    "Company A",
                    company_field="flexipos_company",
                )

    def test_missing_document_is_rejected_without_special_case(self):
        with patch.object(frappe.db, "get_value", return_value=None):
            with self.assertRaises(frappe.PermissionError):
                api._require_document_company(
                    "Sales Invoice", "MISSING", "Company A"
                )

    def test_user_company_requires_one_unambiguous_tenant(self):
        with (
            patch.object(
                frappe,
                "get_all",
                side_effect=[["Company A"], []],
            ),
            patch.object(frappe.db, "exists", return_value=True),
        ):
            self.assertEqual(api._get_user_company(), "Company A")

    def test_conflicting_user_tenants_are_rejected(self):
        with patch.object(
            frappe,
            "get_all",
            side_effect=[["Company A"], ["PROFILE-B"], ["Company B"]],
        ):
            with self.assertRaises(frappe.PermissionError):
                api._get_user_company()

    def test_pos_profile_must_be_owned_and_assigned(self):
        profile = MagicMock()
        profile.company = "Company A"
        profile.disabled = 0
        profile.customer = "Walk-in Customer"
        profile.warehouse = "Stores - A"
        with (
            patch.object(api, "_require_document_company") as require_owner,
            patch.object(frappe.db, "exists", return_value=True),
            patch.object(frappe, "get_cached_doc", return_value=profile),
        ):
            result = api._get_pos_profile_for_company(
                "Company A POS", "Company A", "staff@example.com"
            )
        self.assertIs(result, profile)
        self.assertEqual(require_owner.call_count, 2)

    def test_company_category_image_json_is_safely_parsed(self):
        with patch.object(
            frappe.db,
            "get_value",
            return_value='{"Drinks":"/files/drinks.png","Empty":""}',
        ):
            self.assertEqual(
                api._get_company_category_images("Company A"),
                {"Drinks": "/files/drinks.png"},
            )

    def test_shared_table_key_is_tenant_scoped(self):
        self.assertNotEqual(
            api._table_state_key("Company A", "12"),
            api._table_state_key("Company B", "12"),
        )

    def test_shared_table_round_trip_uses_company_owned_document(self):
        company = frappe.get_all("Company", pluck="name", limit=1)[0]
        table_no = "__flexipos_test_table__"
        name = api._table_state_key(company, table_no)
        if frappe.db.exists("FlexiPOS Table", name):
            frappe.delete_doc("FlexiPOS Table", name, ignore_permissions=True)
        try:
            api._upsert_shared_table(
                company, table_no, "Occupied", "offline-test", "register-test"
            )
            row = frappe.db.get_value(
                "FlexiPOS Table",
                name,
                ["company", "status", "current_offline_invoice_id"],
                as_dict=True,
            )
            self.assertEqual(row.company, company)
            self.assertEqual(row.status, "Occupied")
            self.assertEqual(row.current_offline_invoice_id, "offline-test")
        finally:
            if frappe.db.exists("FlexiPOS Table", name):
                frappe.delete_doc("FlexiPOS Table", name, ignore_permissions=True)

    def test_business_config_parses_lists_without_cross_field_defaults(self):
        values = frappe._dict(
            flexipos_categories='["Cakes", "Bread"]',
            flexipos_default_tax_rate=5,
            flexipos_service_styles="Dine-in,Takeaway",
        )
        with patch.object(frappe.db, "get_value", return_value=values):
            config = api._get_business_config("Company A")
        self.assertEqual(config["categories"], ["Cakes", "Bread"])
        self.assertEqual(config["default_tax_rate"], 5)
        self.assertEqual(config["service_styles"], ["Dine-in", "Takeaway"])


class TestTenantIsolationIntegration(FrappeTestCase):
    """Exercise tenant boundaries against real records, not mocked guards."""

    def setUp(self):
        self.previous_user = frappe.session.user
        frappe.set_user("Administrator")
        companies = frappe.get_all("Company", pluck="name", limit=2)
        if len(companies) < 2:
            self.skipTest("Tenant-isolation tests require two companies")
        self.company_a, self.company_b = companies
        self.suffix = uuid4().hex[:12]
        self.created = []

    def tearDown(self):
        frappe.set_user("Administrator")
        for doctype, name in reversed(getattr(self, "created", [])):
            if frappe.db.exists(doctype, name):
                frappe.delete_doc(doctype, name, ignore_permissions=True)
        frappe.set_user(self.previous_user)

    def _insert(self, doctype, **values):
        doc = frappe.get_doc({"doctype": doctype, **values})
        doc.insert(ignore_permissions=True)
        self.created.append((doctype, doc.name))
        return doc

    def _held_order(self, company, offline_id, register_id):
        return self._insert(
            "FlexiPOS Held Order",
            offline_id=offline_id,
            company=company,
            register_id=register_id,
            order_type="Dine-in",
            grand_total=10,
            item_count=1,
            lines_json='[{"item_code":"TEST","qty":1}]',
            held_at=frappe.utils.now_datetime(),
        )

    def _shift(self, company, shift_id, register_id):
        return self._insert(
            "FlexiPOS Shift",
            shift_id=shift_id,
            company=company,
            register_id=register_id,
            staff_user="Administrator",
            opening_float=100,
            opened_at=frappe.utils.now_datetime(),
            status="Open",
        )

    def _movement(self, company, movement_id, register_id, shift):
        return self._insert(
            "FlexiPOS Cash Movement",
            movement_id=movement_id,
            company=company,
            register_id=register_id,
            shift=shift,
            movement_type="Pay In",
            amount=10,
            created_at=frappe.utils.now_datetime(),
        )

    def test_shared_state_returns_only_the_requested_company(self):
        table_no = f"tenant-table-{self.suffix}"
        table_a = api._table_state_key(self.company_a, table_no)
        table_b = api._table_state_key(self.company_b, table_no)
        api._upsert_shared_table(
            self.company_a, table_no, "Free", None, "register-a"
        )
        self.created.append(("FlexiPOS Table", table_a))
        api._upsert_shared_table(
            self.company_b, table_no, "Occupied", "sale-b", "register-b"
        )
        self.created.append(("FlexiPOS Table", table_b))
        held_a = f"held-a-{self.suffix}"
        held_b = f"held-b-{self.suffix}"
        self._held_order(self.company_a, held_a, "register-a")
        self._held_order(self.company_b, held_b, "register-b")

        state = api._shared_register_state(
            self.company_a, "register-a", include_shift=False
        )
        matching_tables = [
            row for row in state["tables"] if row["table_no"] == table_no
        ]
        held_ids = {row["id"] for row in state["held_orders"]}

        self.assertEqual(len(matching_tables), 1)
        self.assertEqual(matching_tables[0]["register_id"], "register-a")
        self.assertIn(held_a, held_ids)
        self.assertNotIn(held_b, held_ids)

    def test_same_table_number_cannot_overwrite_another_tenant(self):
        table_no = f"collision-{self.suffix}"
        table_a = api._table_state_key(self.company_a, table_no)
        table_b = api._table_state_key(self.company_b, table_no)
        api._upsert_shared_table(
            self.company_a, table_no, "Free", None, "register-a"
        )
        self.created.append(("FlexiPOS Table", table_a))
        api._upsert_shared_table(
            self.company_b, table_no, "Occupied", "sale-b", "register-b"
        )
        self.created.append(("FlexiPOS Table", table_b))

        api._apply_table_operation(
            self.company_a,
            "register-a",
            "table_upsert",
            {
                "table_no": table_no,
                "status": "occupied",
                "current_offline_invoice_id": "sale-a",
            },
        )

        row_a = frappe.db.get_value(
            "FlexiPOS Table",
            table_a,
            ["company", "current_offline_invoice_id", "register_id"],
            as_dict=True,
        )
        row_b = frappe.db.get_value(
            "FlexiPOS Table",
            table_b,
            ["company", "current_offline_invoice_id", "register_id"],
            as_dict=True,
        )
        self.assertEqual(row_a.company, self.company_a)
        self.assertEqual(row_a.current_offline_invoice_id, "sale-a")
        self.assertEqual(row_b.company, self.company_b)
        self.assertEqual(row_b.current_offline_invoice_id, "sale-b")
        self.assertEqual(row_b.register_id, "register-b")

    def test_cross_tenant_held_order_delete_is_rejected(self):
        held_b = f"held-b-{self.suffix}"
        self._held_order(self.company_b, held_b, "register-b")

        operations = json.dumps(
            [{"action": "held_delete", "payload": {"id": held_b}}]
        )
        with (
            patch.object(api, "_require_any_screen_access"),
            patch.object(api, "_get_user_company", return_value=self.company_a),
            patch.object(api, "_validate_register_id", return_value="register-a"),
            patch.object(
                api, "_screen_permissions_for_user", return_value=["held_orders"]
            ),
            self.assertRaises(frappe.PermissionError),
        ):
            api.sync_register_state("register-a", operations)

        self.assertTrue(frappe.db.exists("FlexiPOS Held Order", held_b))

    def test_cross_tenant_cash_movement_is_rejected(self):
        shift_b = f"shift-b-{self.suffix}"
        self._shift(self.company_b, shift_b, "register-b")

        with self.assertRaises(frappe.PermissionError):
            api._apply_shift_operation(
                self.company_a,
                "register-a",
                "movement_upsert",
                {
                    "movement_id": f"movement-a-{self.suffix}",
                    "shift_id": shift_b,
                    "type": "pay_in",
                    "amount": 10,
                },
            )

        self.assertFalse(
            frappe.db.exists(
                "FlexiPOS Cash Movement", f"movement-a-{self.suffix}"
            )
        )

    def test_shift_snapshot_is_scoped_to_company_and_register(self):
        shift_a1 = f"shift-a1-{self.suffix}"
        shift_a2 = f"shift-a2-{self.suffix}"
        shift_b1 = f"shift-b1-{self.suffix}"
        self._shift(self.company_a, shift_a1, "register-a")
        self._shift(self.company_a, shift_a2, "register-a-other")
        self._shift(self.company_b, shift_b1, "register-a")
        movement_a1 = f"movement-a1-{self.suffix}"
        movement_a2 = f"movement-a2-{self.suffix}"
        self._movement(
            self.company_a, movement_a1, "register-a", shift_a1
        )
        self._movement(
            self.company_a, movement_a2, "register-a-other", shift_a2
        )

        state = api._shared_register_state(
            self.company_a, "register-a", include_shift=True
        )

        self.assertEqual({row["id"] for row in state["shifts"]}, {shift_a1})
        self.assertEqual(
            {row["movement_id"] for row in state["cash_movements"]},
            {movement_a1},
        )

    def test_invoice_batch_rejects_payload_for_another_company(self):
        payload = {
            "offline_invoice_id": f"cross-tenant-sale-{self.suffix}",
            "company": self.company_b,
            "items": [{"item_code": "ANY", "qty": 1}],
        }
        with (
            patch.object(api, "_require_screen_access"),
            patch.object(api, "_get_user_company", return_value=self.company_a),
            patch.object(api, "_create_pos_invoice") as create_invoice,
        ):
            response = api.push_offline_invoices(json.dumps([payload]))

        self.assertEqual(response["results"][0]["status"], "failed")
        self.assertIn("Not permitted", response["results"][0]["error"])
        create_invoice.assert_not_called()


class TestAuthoritativePricing(FrappeTestCase):
    def test_price_estimate_tolerance_is_small_and_finite(self):
        self.assertTrue(api._estimate_matches(100, 100.009))
        self.assertFalse(api._estimate_matches(100, 100.02))
        self.assertFalse(api._estimate_matches(100, float("nan")))

    def test_customer_price_wins_and_expired_prices_are_ignored(self):
        rows = [
            frappe._dict(
                price_list_rate=90,
                uom="Nos",
                customer=None,
                batch_no=None,
                valid_from="2026-01-01",
                valid_upto=None,
            ),
            frappe._dict(
                price_list_rate=80,
                uom="Nos",
                customer="CUSTOMER-1",
                batch_no=None,
                valid_from="2026-01-01",
                valid_upto="2026-06-30",
            ),
            frappe._dict(
                price_list_rate=85,
                uom="Nos",
                customer="CUSTOMER-1",
                batch_no=None,
                valid_from="2026-07-01",
                valid_upto=None,
            ),
        ]
        with patch.object(frappe, "get_all", return_value=rows):
            rate = api._get_authoritative_item_price(
                "ITEM-1",
                "Standard Selling",
                "Nos",
                "CUSTOMER-1",
                "2026-07-13",
            )
        self.assertEqual(rate, 85)

    def test_modifier_price_is_resolved_from_server_option(self):
        group = frappe._dict(
            name="GROUP-1",
            group_name="Add-ons",
            flexipos_company="Company A",
            selection_type="Multiple",
            required=0,
            min_select=0,
            max_select=3,
            options=[frappe._dict(label="Cheese", price=25)],
        )
        links = [frappe._dict(modifier_group="GROUP-1", idx=1)]
        with (
            patch.object(frappe, "get_all", return_value=links),
            patch.object(frappe, "get_cached_doc", return_value=group),
        ):
            resolved = api._resolve_authoritative_modifiers(
                "ITEM-1",
                "Company A",
                [{"group": "Add-ons", "label": "Cheese", "price": 999}],
            )
        self.assertEqual(resolved[0]["price"], 25)


class TestEndpointPermissionContract(FrappeTestCase):
    """Prevent future endpoints from accidentally losing their API guard."""

    account_lifecycle_endpoints: ClassVar[set[str]] = {
        "register_business",
        "get_my_business",
        "get_device_token",
        "register_device_pin",
        "verify_pin_login",
        "request_login_otp",
        "verify_login_otp",
    }

    required_guards: ClassVar[dict[str, set[str]]] = {
        "setup_new_business": {"_require_business_setup_access"},
        "sync_inventory": {"_require_any_screen_access"},
        "save_business_setup": {"_require_screen_access", "_require_admin"},
        "sync_register_state": {"_require_any_screen_access"},
        "save_item": {"_require_screen_access"},
        "lookup_item_by_barcode": {"_require_any_screen_access"},
        "save_modifier_group": {"_require_screen_access"},
        "delete_modifier_group": {"_require_screen_access"},
        "upload_image": {"_require_screen_access"},
        "push_offline_invoices": {"_require_screen_access"},
        "update_kitchen_status": {"_require_screen_access"},
        "process_refund": {"_require_screen_access"},
        "get_order_history": {"_require_screen_access"},
        "list_staff": {"_require_screen_access", "_require_admin"},
        "add_staff": {"_require_screen_access", "_require_admin"},
        "update_staff": {"_require_screen_access", "_require_admin"},
        "remove_staff": {"_require_screen_access", "_require_admin"},
    }

    ownership_guards: ClassVar[dict[str, set[str]]] = {
        "get_my_business": {"_get_user_company", "_get_pos_profile_for_company"},
        "save_item": {"_require_document_company"},
        "sync_register_state": {"_get_user_company"},
        "_assign_modifier_groups": {"_require_document_company"},
        "save_modifier_group": {"_require_document_company"},
        "delete_modifier_group": {"_require_document_company"},
        "upload_image": {"_require_document_company"},
        "_create_pos_invoice": {
            "_get_pos_profile_for_company",
            "_require_document_company",
            "_get_authoritative_item_price",
            "_resolve_authoritative_modifiers",
            "_get_output_tax_account",
        },
        "update_kitchen_status": {"_require_document_company"},
        "process_refund": {"_require_document_company"},
        "update_staff": {"_require_staff_of_company"},
        "remove_staff": {"_require_staff_of_company"},
    }

    def test_business_endpoints_have_required_guards(self):
        source = Path(api.__file__).read_text()
        module = ast.parse(source)
        functions = {
            node.name: node
            for node in module.body
            if isinstance(node, ast.FunctionDef)
        }

        for function_name, expected in self.required_guards.items():
            with self.subTest(endpoint=function_name):
                calls = {
                    node.func.id
                    for node in ast.walk(functions[function_name])
                    if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                }
                self.assertTrue(expected.issubset(calls), expected - calls)

    def test_every_whitelisted_endpoint_is_classified(self):
        source = Path(api.__file__).read_text()
        module = ast.parse(source)
        whitelisted = set()
        for node in module.body:
            if not isinstance(node, ast.FunctionDef):
                continue
            for decorator in node.decorator_list:
                target = (
                    decorator.func
                    if isinstance(decorator, ast.Call)
                    else decorator
                )
                if (
                    isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and target.value.id == "frappe"
                    and target.attr == "whitelist"
                ):
                    whitelisted.add(node.name)

        classified = set(self.required_guards) | self.account_lifecycle_endpoints
        self.assertEqual(whitelisted, classified)

    def test_document_references_keep_their_ownership_guards(self):
        source = Path(api.__file__).read_text()
        module = ast.parse(source)
        functions = {
            node.name: node
            for node in module.body
            if isinstance(node, ast.FunctionDef)
        }

        for function_name, expected in self.ownership_guards.items():
            with self.subTest(function=function_name):
                calls = {
                    node.func.id
                    for node in ast.walk(functions[function_name])
                    if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                }
                self.assertTrue(expected.issubset(calls), expected - calls)
