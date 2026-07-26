import ast
import hashlib
import io
import json
import urllib.error
from pathlib import Path
from typing import ClassVar
from unittest.mock import MagicMock, patch
from uuid import uuid4

import frappe
from frappe.tests.utils import FrappeTestCase

from flexipos import api, security


class TestSecurityHeaders(FrappeTestCase):
    def test_https_security_headers_are_added_to_responses(self):
        security.add_security_headers()

        self.assertEqual(
            frappe.local.response_headers.get("Strict-Transport-Security"),
            "max-age=31536000; includeSubDomains",
        )
        self.assertEqual(
            frappe.local.response_headers.get("X-Content-Type-Options"),
            "nosniff",
        )


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


class TestLaunchNicheScope(FrappeTestCase):
    def test_retail_and_restaurant_can_be_provisioned(self):
        self.assertEqual(api._validate_launch_business_type("retail"), "Retail")
        self.assertEqual(
            api._validate_launch_business_type("Restaurant"), "Restaurant"
        )

    def test_unfinished_niches_cannot_be_self_provisioned(self):
        for value in ("Pharmacy", "Clothing", "Bakery", "Service", "Other"):
            with self.subTest(value=value), self.assertRaises(frappe.ValidationError):
                api._validate_launch_business_type(value)


class TestSaaSOperatorPortal(FrappeTestCase):
    def test_tenant_list_includes_safe_operator_metadata(self):
        row = frappe._dict(
            name="Company A",
            company_name="Company A",
            creation="2026-07-01 10:00:00",
            modified="2026-07-26 10:00:00",
            flexipos_business_type="Restaurant",
        )
        with (
            patch.object(api, "_require_saas_operator"),
            patch.object(frappe, "get_all", return_value=[row]),
            patch.object(
                api,
                "_subscription_payload",
                return_value={
                    "status": "Trialing",
                    "trial_ends_on": "2026-08-01 10:00:00",
                    "billing_email": "billing@example.com",
                },
            ),
            patch.object(api, "_default_trial_days", return_value=30),
        ):
            result = api.saas_list_tenants(limit=500)

        self.assertEqual(result["default_trial_days"], 30)
        self.assertEqual(result["tenants"][0]["company"], "Company A")
        self.assertEqual(result["tenants"][0]["business_type"], "Restaurant")
        self.assertEqual(result["tenants"][0]["status"], "Trialing")
        self.assertNotIn("api_secret", result["tenants"][0])
        self.assertNotIn("customer_token", result["tenants"][0])

    def test_operator_page_is_role_scoped_and_uses_guarded_lifecycle_apis(self):
        app_root = Path(api.__file__).parent
        page_root = (
            app_root
            / "flexipos"
            / "page"
            / "flexipos_saas_console"
        )
        manifest = json.loads(
            (page_root / "flexipos_saas_console.json").read_text()
        )
        script = (page_root / "flexipos_saas_console.js").read_text()
        settings_script = (
            app_root / "public" / "js" / "flexipos_saas_settings.js"
        ).read_text()

        self.assertEqual(manifest["roles"], [{"role": "System Manager"}])
        self.assertIn("flexipos.api.saas_list_tenants", script)
        self.assertIn("flexipos.api.saas_extend_trial", script)
        self.assertIn("flexipos.api.saas_set_tenant_status", script)
        self.assertNotIn("secret_api_key", script)
        self.assertNotIn("webhook_secret", script)
        self.assertIn('frappe.set_route("flexipos-saas-console")', settings_script)


class TestSubscriptionLifecycle(FrappeTestCase):
    def test_first_pin_starts_configured_trial_and_returns_fresh_status(self):
        fixed_now = frappe.utils.get_datetime("2026-07-22 12:00:00")
        lifecycle = {
            "subscription_status": "trialing",
            "trial_ends_at": "2026-08-21 12:00:00",
            "billing_setup_required": False,
        }
        with (
            patch.object(
                frappe.db,
                "get_value",
                side_effect=[None, "Past Due"],
            ),
            patch.object(frappe.db, "set_value") as set_value,
            patch.object(api, "_get_user_company", return_value="Company A"),
            patch.object(api, "_is_company_owner", return_value=True),
            patch.object(api, "_payment_gateway_disabled", return_value=False),
            patch.object(api, "_default_trial_days", return_value=30),
            patch.object(api, "now_datetime", return_value=fixed_now),
            patch.object(
                api,
                "_subscription_client_payload",
                return_value=lifecycle,
            ),
        ):
            result = api.register_device_pin("1234", "device-a")

        company_update = set_value.call_args_list[1]
        self.assertEqual(company_update.args[:2], ("Company", "Company A"))
        self.assertEqual(
            company_update.args[2][api.SUBSCRIPTION_STATUS_FIELD], "Trialing"
        )
        self.assertEqual(
            company_update.args[2][api.TRIAL_ENDS_FIELD],
            frappe.utils.add_to_date(fixed_now, days=30),
        )
        self.assertEqual(result["subscription_status"], "trialing")
        self.assertFalse(result["billing_setup_required"])

    def test_replacing_an_existing_pin_never_extends_trial(self):
        with (
            patch.object(
                frappe.db,
                "get_value",
                side_effect=["salt$existing-hash", "Past Due"],
            ),
            patch.object(frappe.db, "set_value") as set_value,
            patch.object(api, "_get_user_company", return_value="Company A"),
            patch.object(
                api,
                "_subscription_client_payload",
                return_value={"subscription_status": "past_due"},
            ),
        ):
            api.register_device_pin("1234", "device-b")

        self.assertEqual(set_value.call_count, 1)
        self.assertEqual(set_value.call_args.args[0], "User")

    def test_staff_first_pin_cannot_revive_an_expired_tenant(self):
        with (
            patch.object(
                frappe.db,
                "get_value",
                side_effect=[None, "Past Due"],
            ),
            patch.object(frappe.db, "set_value") as set_value,
            patch.object(api, "_get_user_company", return_value="Company A"),
            patch.object(api, "_is_company_owner", return_value=False),
            patch.object(
                api,
                "_subscription_client_payload",
                return_value={"subscription_status": "past_due"},
            ),
        ):
            result = api.register_device_pin("1234", "staff-device")

        self.assertEqual(set_value.call_count, 1)
        self.assertEqual(set_value.call_args.args[0], "User")
        self.assertEqual(result["subscription_status"], "past_due")

    def test_expired_trial_is_marked_past_due(self):
        values = frappe._dict(
            flexipos_subscription_status="Trialing",
            flexipos_trial_ends_on=frappe.utils.add_to_date(
                frappe.utils.now_datetime(), days=-1
            ),
            flexipos_current_period_end=None,
            flexipos_billing_provider=None,
            flexipos_billing_plan=None,
            flexipos_billing_email=None,
            flexipos_deletion_requested_at=None,
            flexipos_retention_until=None,
        )
        with (
            patch.object(frappe.db, "get_value", return_value=values),
            patch.object(frappe.db, "set_value") as set_value,
            patch.object(
                api,
                "_get_saas_settings",
                return_value=frappe._dict(
                    require_payment_method_on_signup=0,
                    terms_url=None,
                    privacy_url=None,
                ),
            ),
        ):
            subscription = api._subscription_payload("Company A")
        self.assertEqual(subscription["status"], "Past Due")
        set_value.assert_called_once()

    def test_non_operational_subscription_is_blocked(self):
        with (
            patch.object(api, "_get_user_company", return_value="Company A"),
            patch.object(
                api,
                "_subscription_payload",
                return_value={"status": "Past Due"},
            ),
        ):
            with self.assertRaises(frappe.PermissionError):
                api._require_subscription_access()

    def test_free_access_bypasses_payment_status_but_not_suspension(self):
        with (
            patch.object(api, "_get_user_company", return_value="Company A"),
            patch.object(
                api,
                "_subscription_payload",
                return_value={
                    "status": "Past Due",
                    "payment_gateway_disabled": True,
                },
            ),
        ):
            subscription = api._require_subscription_access()
        self.assertEqual(subscription["status"], "Past Due")

        with (
            patch.object(api, "_get_user_company", return_value="Company A"),
            patch.object(
                api,
                "_subscription_payload",
                return_value={
                    "status": "Suspended",
                    "payment_gateway_disabled": True,
                },
            ),
        ):
            with self.assertRaises(frappe.PermissionError):
                api._require_subscription_access()

    def test_client_payload_is_normalized_for_flutter(self):
        with patch.object(
            api,
            "_subscription_payload",
            return_value={
                "status": "Past Due",
                "plan": "monthly",
                "billing_provider": "safepay",
                "trial_ends_on": None,
                "current_period_end": None,
                "billing_setup_required": True,
            },
        ):
            payload = api._subscription_client_payload("Company A")
        self.assertEqual(payload["subscription_status"], "past_due")
        self.assertTrue(payload["billing_setup_required"])

    def test_free_access_is_active_for_flutter_and_never_requires_billing(self):
        with patch.object(
            api,
            "_subscription_payload",
            return_value={
                "status": "Past Due",
                "plan": "monthly",
                "billing_provider": None,
                "trial_ends_on": None,
                "current_period_end": None,
                "billing_setup_required": True,
                "payment_gateway_disabled": True,
            },
        ):
            payload = api._subscription_client_payload("Company A")
        self.assertEqual(payload["subscription_status"], "active")
        self.assertFalse(payload["billing_setup_required"])
        self.assertTrue(payload["payment_gateway_disabled"])

    def test_free_access_does_not_expire_an_existing_trial(self):
        values = frappe._dict(
            flexipos_subscription_status="Trialing",
            flexipos_trial_ends_on=frappe.utils.add_to_date(
                frappe.utils.now_datetime(), days=-1
            ),
            flexipos_current_period_end=None,
            flexipos_billing_provider=None,
            flexipos_billing_plan=None,
            flexipos_billing_email=None,
            flexipos_deletion_requested_at=None,
            flexipos_retention_until=None,
        )
        with (
            patch.object(frappe.db, "get_value", return_value=values),
            patch.object(frappe.db, "set_value") as set_value,
            patch.object(
                api,
                "_get_saas_settings",
                return_value=frappe._dict(
                    disable_payment_gateway=1,
                    require_payment_method_on_signup=1,
                    billing_enabled=1,
                    billing_provider="Safepay",
                    terms_url=None,
                    privacy_url=None,
                ),
            ),
        ):
            subscription = api._subscription_payload("Company A")
        self.assertEqual(subscription["status"], "Trialing")
        self.assertTrue(subscription["payment_gateway_disabled"])
        self.assertFalse(subscription["billing_setup_required"])
        set_value.assert_not_called()

    def test_cross_tenant_controls_require_site_administrator(self):
        previous = frappe.session.user
        try:
            frappe.set_user("Guest")
            with self.assertRaises(frappe.PermissionError):
                api._require_saas_operator()
        finally:
            frappe.set_user(previous)

    def test_client_cannot_register_its_own_payment_token(self):
        with (
            patch.object(api, "_get_user_company", return_value="Company A"),
            patch.object(api, "_require_admin"),
            patch.object(frappe.db, "set_value") as set_value,
        ):
            with self.assertRaises(frappe.PermissionError):
                api.start_billing_checkout(
                    "monthly",
                    provider="safepay",
                    billing_email="owner@example.com",
                    customer_token="client-supplied-token",
                    privacy_consent=True,
                )
        set_value.assert_not_called()

    def test_safepay_event_requires_explicit_success(self):
        self.assertIsNone(
            api._safepay_event_status(
                "subscription.created", {"status": "pending"}
            )
        )
        self.assertEqual(
            api._safepay_event_status(
                "subscription.payment_succeeded", {"status": "paid"}
            ),
            "Active",
        )
        self.assertEqual(
            api._safepay_event_status(
                "subscription.cancelled", {"status": "cancelled"}
            ),
            "Cancelled",
        )

    def test_nested_checkout_reference_is_found(self):
        payload = {"subscription": {"metadata": {"reference": "sprout_123"}}}
        self.assertEqual(
            api._find_billing_value(payload, {"reference"}), "sprout_123"
        )

    def test_safepay_checkout_url_contains_token_but_not_secret(self):
        response = MagicMock()
        response.read.return_value = b'{"data":"short-lived-token"}'
        response.__enter__.return_value = response
        settings = frappe._dict(
            sandbox_mode=1,
            secret_api_key="merchant-secret",
        )
        with patch.object(api.urllib.request, "urlopen", return_value=response):
            url = api._create_safepay_subscription_url(
                settings,
                "plan_123",
                "sprout_ref",
                "https://example.com/success",
                "https://example.com/cancel",
            )
        self.assertIn("sandbox.api.getsafepay.com/checkout/subscribe", url)
        self.assertIn("auth_token=short-lived-token", url)
        self.assertIn("reference=sprout_ref", url)
        self.assertNotIn("merchant-secret", url)

    def test_safepay_secret_is_trimmed_before_authentication(self):
        response = MagicMock()
        response.read.return_value = b'{"data":"short-lived-token"}'
        response.__enter__.return_value = response
        settings = frappe._dict(
            sandbox_mode=1,
            secret_api_key="  merchant-secret\n",
        )
        with patch.object(
            api.urllib.request, "urlopen", return_value=response
        ) as urlopen:
            api._create_safepay_subscription_url(
                settings,
                "plan_123",
                "sprout_ref",
                "https://example.com/success",
                "https://example.com/cancel",
            )
        request = urlopen.call_args.args[0]
        self.assertEqual(
            request.get_header("X-sfpy-merchant-secret"), "merchant-secret"
        )
        self.assertEqual(request.get_header("User-agent"), "FlexiPOS-SaaS/1.0")

    def test_safepay_auth_rejection_explains_environment_mismatch(self):
        settings = frappe._dict(
            sandbox_mode=1,
            secret_api_key="invalid-secret",
        )
        error = urllib.error.HTTPError(
            "https://sandbox.api.getsafepay.com/client/passport/v1/token",
            401,
            "Unauthorized",
            {},
            io.BytesIO(b'{"status":{"message":"fail"}}'),
        )
        with (
            patch.object(api.urllib.request, "urlopen", side_effect=error),
            patch.object(frappe, "log_error"),
            self.assertRaisesRegex(Exception, "Secret API Key.*sandbox"),
        ):
            api._create_safepay_subscription_url(
                settings,
                "plan_123",
                "sprout_ref",
                "https://example.com/success",
                "https://example.com/cancel",
            )

    def test_safepay_forbidden_response_is_not_reported_as_bad_key(self):
        settings = frappe._dict(
            sandbox_mode=1,
            secret_api_key="valid-secret",
        )
        error = urllib.error.HTTPError(
            "https://sandbox.api.getsafepay.com/client/passport/v1/token",
            403,
            "Forbidden",
            {},
            io.BytesIO(b"forbidden"),
        )
        with (
            patch.object(api.urllib.request, "urlopen", side_effect=error),
            patch.object(frappe, "log_error"),
            self.assertRaisesRegex(Exception, "refused checkout requests.*403"),
        ):
            api._create_safepay_subscription_url(
                settings,
                "plan_123",
                "sprout_ref",
                "https://example.com/success",
                "https://example.com/cancel",
            )


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
    def test_minor_unit_rounding_is_half_up(self):
        self.assertEqual(api._money_minor("10.004"), 1000)
        self.assertEqual(api._money_minor("10.005"), 1001)
        self.assertEqual(api._money_minor("-10.005"), -1001)
        self.assertEqual(str(api._money_decimal("3.335")), "3.34")

    def test_minor_unit_contract_rejects_mismatch(self):
        api._require_matching_minor(
            {"amount_minor": 1001}, "amount_minor", "10.01", label="payment"
        )
        with self.assertRaises(frappe.ValidationError):
            api._require_matching_minor(
                {"amount_minor": 1000},
                "amount_minor",
                "10.01",
                label="payment",
            )

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


class TestCommerceIntegrity(FrappeTestCase):
    def test_staff_cannot_push_promotion_changes(self):
        with (
            patch.object(api, "_require_screen_access"),
            patch.object(api, "_get_user_company", return_value="Company A"),
            patch.object(api, "_effective_role", return_value="Staff"),
        ):
            with self.assertRaises(frappe.PermissionError):
                api.sync_commerce(
                    promotions_json=json.dumps(
                        [{"promotion_id": "promotion-1", "title": "Offer"}]
                    )
                )

    def test_partial_loyalty_refunds_round_and_converge(self):
        self.assertEqual(api._prorated_points(7, 5000, 10000), 4)
        self.assertEqual(api._prorated_points(7, 10000, 10000), 7)
        self.assertEqual(api._prorated_points(7, 15000, 10000), 7)

    def test_shared_kitchen_order_keeps_customer_adjustments_and_modifiers(self):
        invoice = frappe._dict(
            name="SINV-DRAFT-1",
            flexipos_offline_id="draft-1",
            flexipos_order_type="Dine-in",
            flexipos_table_no="4",
            flexipos_kitchen_status="Placed",
            flexipos_register_id="register-1",
            flexipos_customer_id="customer-1",
            flexipos_adjustments_json=json.dumps(
                [
                    {
                        "type": "promotion",
                        "label": "Summer 10%",
                        "amount_minor": 1000,
                        "reference": "promotion-1",
                    }
                ]
            ),
            customer="ERP-CUSTOMER-1",
            posting_date="2026-07-22",
            posting_time="12:00:00",
            net_total=90,
            total_taxes_and_charges=0,
            discount_amount=10,
            grand_total=90,
            paid_amount=0,
        )
        item = frappe._dict(
            parent=invoice.name,
            item_code="ITEM-1",
            item_name="Burger",
            qty=1,
            rate=100,
            flexipos_modifiers_json=json.dumps(
                [{"group": "Extras", "label": "Cheese", "price": 5}]
            ),
            idx=1,
        )
        with patch.object(
            frappe,
            "get_all",
            side_effect=[
                [invoice],
                [item],
                [frappe._dict(name="ITEM-1", flexipos_tax_rate=0)],
                [],
                [frappe._dict(name="customer-1", customer_name="Ayesha Khan")],
            ],
        ):
            result = api._shared_kitchen_orders("Company A")

        self.assertEqual(result[0]["customer"], "customer-1")
        self.assertEqual(result[0]["customer_name"], "Ayesha Khan")
        self.assertEqual(result[0]["discount_total_minor"], 1000)
        self.assertEqual(result[0]["adjustments"][0]["reference"], "promotion-1")
        self.assertEqual(result[0]["items"][0]["modifiers"][0]["label"], "Cheese")

    def test_customer_selection_rejects_cross_tenant_customer(self):
        profile = frappe._dict(customer="Walk-in Customer")
        customer = frappe._dict(
            name="customer-1",
            company="Company B",
            disabled=0,
            linked_customer="ERP-CUSTOMER-1",
        )
        with patch.object(frappe, "get_doc", return_value=customer):
            with self.assertRaises(frappe.PermissionError):
                api._resolve_sale_customer("Company A", profile, "customer-1")

    def test_promotion_is_recalculated_and_capped_by_the_server(self):
        promotion = frappe._dict(
            name="promotion-1",
            company="Company A",
            active=1,
            title="Launch discount",
            starts_at=None,
            ends_at=None,
            usage_limit=0,
            used_count=0,
            minimum_spend_minor=10000,
            discount_type="Percentage",
            percentage_basis_points=1250,
            fixed_amount_minor=0,
            maximum_discount_minor=1000,
        )
        payload = {
            "adjustments": [
                {
                    "type": "promotion",
                    "reference": "promotion-1",
                    "amount_minor": 1000,
                }
            ],
            "discount_total_minor": 1000,
        }
        with (
            patch.object(
                frappe.db,
                "sql",
                return_value=[frappe._dict(name="promotion-1")],
            ),
            patch.object(frappe, "get_doc", return_value=promotion),
        ):
            resolved, total, selected, redeemed = api._resolve_sale_adjustments(
                payload,
                company="Company A",
                customer=None,
                server_gross_minor=10005,
                posting=frappe.utils.get_datetime("2026-07-22 12:00:00"),
                user="cashier@example.test",
            )

        self.assertEqual(total, 1000)
        self.assertEqual(resolved[0]["amount_minor"], 1000)
        self.assertEqual(selected.name, "promotion-1")
        self.assertEqual(redeemed, 0)

    def test_loyalty_redemption_locks_and_rejects_stale_balance(self):
        customer = frappe._dict(name="customer-1")
        payload = {
            "adjustments": [
                {
                    "type": "loyalty",
                    "amount_minor": 500,
                    "loyalty_points": 5,
                }
            ],
            "discount_total_minor": 500,
        }
        with patch.object(
            frappe.db,
            "sql",
            return_value=[frappe._dict(loyalty_points=4)],
        ):
            with self.assertRaises(frappe.ValidationError):
                api._resolve_sale_adjustments(
                    payload,
                    company="Company A",
                    customer=customer,
                    server_gross_minor=10000,
                    posting=frappe.utils.get_datetime("2026-07-22 12:00:00"),
                    user="cashier@example.test",
                )

    def test_manual_discount_requires_manager_and_a_reason(self):
        payload = {
            "adjustments": [
                {"type": "manual", "amount_minor": 100, "reason": "Late order"}
            ],
            "discount_total_minor": 100,
        }
        with patch.object(api, "_effective_role", return_value="Staff"):
            with self.assertRaises(frappe.PermissionError):
                api._resolve_sale_adjustments(
                    payload,
                    company="Company A",
                    customer=None,
                    server_gross_minor=10000,
                    posting=frappe.utils.get_datetime("2026-07-22 12:00:00"),
                    user="cashier@example.test",
                )


class TestFinancialIntegrity(FrappeTestCase):
    def test_sale_requires_a_shift_covering_the_posting_time(self):
        with patch.object(frappe.db, "sql", return_value=[]):
            with self.assertRaises(frappe.ValidationError):
                api._require_shift_covering_sale(
                    "Company A", "register-1", "2026-07-19 10:00:00"
                )
        with patch.object(
            frappe.db, "sql", return_value=[frappe._dict(name="shift-1")]
        ):
            self.assertEqual(
                api._require_shift_covering_sale(
                    "Company A", "register-1", "2026-07-19 10:00:00"
                ),
                "shift-1",
            )

    def test_audit_append_rejects_tampered_hash(self):
        staff_user = frappe.session.user
        details_json = '{"amount_minor":1005}'
        payload = {
            "id": "audit-1",
            "company": "Company A",
            "register_id": "register-1",
            "staff_user": staff_user,
            "event_type": "sale_recorded",
            "entity_type": "offline_invoice",
            "entity_id": "sale-1",
            "details_json": details_json,
            "previous_hash": "",
            "created_at": "2026-07-19T10:00:00.000Z",
        }
        digest_input = json.dumps(
            [
                payload["id"],
                payload["company"],
                payload["register_id"],
                staff_user,
                payload["event_type"],
                payload["entity_type"],
                payload["entity_id"],
                details_json,
                "",
                payload["created_at"],
            ],
            ensure_ascii=False,
            separators=(",", ":"),
        )
        payload["event_hash"] = hashlib.sha256(
            digest_input.encode("utf-8")
        ).hexdigest()
        document = MagicMock()
        with (
            patch.object(frappe.db, "exists", return_value=False),
            patch.object(frappe.db, "get_value", return_value=""),
            patch.object(frappe, "get_doc", return_value=document),
        ):
            api._apply_audit_operation("Company A", "register-1", payload)
        document.insert.assert_called_once_with(ignore_permissions=True)

        payload["event_hash"] = "0" * 64
        with (
            patch.object(frappe.db, "exists", return_value=False),
            patch.object(frappe.db, "get_value", return_value=""),
            self.assertRaises(frappe.ValidationError),
        ):
            api._apply_audit_operation("Company A", "register-1", payload)


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
        "get_subscription",
        "get_subscription_status",
        "start_billing_checkout",
        "create_billing_checkout",
        "admin_set_subscription",
        "cancel_subscription",
        "billing_webhook",
        "billing_checkout_return",
        "safepay_webhook",
        "request_data_export",
        "request_data_deletion",
        "request_account_deletion",
        "cancel_data_deletion",
        "saas_list_tenants",
        "saas_set_default_trial_days",
        "saas_extend_trial",
        "saas_set_tenant_status",
    }

    required_guards: ClassVar[dict[str, set[str]]] = {
        "setup_new_business": {"_require_business_setup_access"},
        "sync_commerce": {"_require_screen_access"},
        "sync_inventory": {"_require_any_screen_access"},
        "save_business_setup": {"_require_screen_access", "_require_admin"},
        "sync_register_state": {"_require_any_screen_access"},
        "save_item": {"_require_screen_access"},
        "lookup_item_by_barcode": {"_require_any_screen_access"},
        "save_modifier_group": {"_require_screen_access"},
        "delete_modifier_group": {"_require_screen_access"},
        "upload_image": {"_require_screen_access"},
        "authorize_pos_payment": {"_require_screen_access"},
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
        "sync_commerce": {"_get_user_company"},
        "save_item": {"_require_document_company"},
        "sync_register_state": {"_get_user_company"},
        "_assign_modifier_groups": {"_require_document_company"},
        "save_modifier_group": {"_require_document_company"},
        "delete_modifier_group": {"_require_document_company"},
        "upload_image": {"_require_document_company"},
        "authorize_pos_payment": {"_get_user_company", "_get_pos_profile_for_company"},
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
