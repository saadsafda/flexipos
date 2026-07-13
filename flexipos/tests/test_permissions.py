import ast
from pathlib import Path
from unittest.mock import MagicMock, patch

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


class TestEndpointPermissionContract(FrappeTestCase):
    """Prevent future endpoints from accidentally losing their API guard."""

    account_lifecycle_endpoints = {
        "register_business",
        "get_my_business",
        "get_device_token",
        "register_device_pin",
        "verify_pin_login",
        "request_login_otp",
        "verify_login_otp",
    }

    required_guards = {
        "setup_new_business": {"_require_business_setup_access"},
        "sync_inventory": {"_require_any_screen_access"},
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

    ownership_guards = {
        "get_my_business": {"_get_user_company", "_get_pos_profile_for_company"},
        "save_item": {"_require_document_company"},
        "_assign_modifier_groups": {"_require_document_company"},
        "save_modifier_group": {"_require_document_company"},
        "delete_modifier_group": {"_require_document_company"},
        "upload_image": {"_require_document_company"},
        "_create_pos_invoice": {
            "_get_pos_profile_for_company",
            "_require_document_company",
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
