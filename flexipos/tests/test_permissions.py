import ast
from pathlib import Path
from unittest.mock import patch

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
