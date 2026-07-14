"""FlexiPOS API layer.

Whitelisted endpoints consumed by the FlexiPOS Flutter client.

Every endpoint returns a plain JSON-serialisable dict. Business data is
mapped onto standard ERPNext DocTypes (Company, Branch, POS Profile,
Item, Item Price, Sales Invoice) wherever possible. Two deliberate
exceptions to the "no custom DocTypes" default:
  - "FlexiPOS OTP": new-device login codes.
  - "FlexiPOS Modifier" (master) / "FlexiPOS Modifier Group" /
    "FlexiPOS Modifier Option" (child) / "FlexiPOS Item Modifier Group"
    (child, on Item): item modifiers with real group semantics
    (single/multiple choice, required, min/max) — the old model
    (add-ons as plain Items pointing at a parent) had no way to express
    "choose 1 of N" or "required", so it was replaced rather than
    layered on top of. Each option row links a reusable FlexiPOS
    Modifier master, so one modifier (e.g. "Extra Cheese") can appear
    in any number of groups.

Custom Fields used (created by `setup_custom_fields`, wire it into
hooks.py as:  after_install = "flexipos.api.setup_custom_fields"):
    Sales Invoice.flexipos_offline_id  (unique, idempotency key)
    Sales Invoice.flexipos_order_type
    Sales Invoice.flexipos_table_no
    Sales Invoice.flexipos_kitchen_status
    Company.flexipos_business_type
    Company.flexipos_phone
    Company.flexipos_category_images
    Branch.flexipos_company
    User.flexipos_pin_hash
    User.flexipos_device_id
    Item.flexipos_company
    Item.flexipos_modifier_groups (Table → FlexiPOS Item Modifier Group)
    Item.flexipos_requires_prescription (Pharmacy: Rx badge)
    Item.flexipos_cold_chain (Pharmacy: cold-chain badge)
    Item.flexipos_duration_minutes (Service duration / Restaurant prep time)
    Item.flexipos_material (Clothing: fabric label)
    Item.flexipos_season (Clothing: season/collection label)
    Item.flexipos_gender (Clothing: Men/Women/Unisex/Kids)
    Item.flexipos_variant_matrix (Clothing: size x colour stock matrix, JSON)
    Item.flexipos_tax_rate (item tax %, stored per item)
    Item.flexipos_stock_qty (simple on-hand count, not ledger stock)
    Item.flexipos_dietary_flags (Restaurant: CSV, e.g. "Halal,Gluten-free")
    Item.flexipos_recipe_depletion (Restaurant: recipe/BOM depletion flag)

Barcodes reuse ERPNext's standard Item.barcodes child table (Item
Barcode) rather than a new field — see sync_inventory/save_item/
lookup_item_by_barcode.
"""

import base64
import hashlib
import hmac
import json
import math
import secrets

import frappe
from frappe import _
from frappe.utils import (
    add_to_date,
    cint,
    flt,
    get_datetime,
    now_datetime,
    validate_email_address,
)

DEFAULT_CURRENCY = "PKR"
BUSINESS_TYPES = ["Restaurant", "Pharmacy", "Retail", "Service", "Clothing", "Bakery", "Other"]
DEFAULT_COUNTRY = "Pakistan"
DEFAULT_PRICE_LIST = "Standard Selling"
WALK_IN_CUSTOMER = "Walk-in Customer"

OFFLINE_ID_FIELD = "flexipos_offline_id"
ORDER_TYPE_FIELD = "flexipos_order_type"
TABLE_FIELD = "flexipos_table_no"
KITCHEN_STATUS_FIELD = "flexipos_kitchen_status"
REGISTER_ID_FIELD = "flexipos_register_id"
KITCHEN_STATUSES = ["Placed", "Preparing", "Ready", "Served"]
PIN_HASH_FIELD = "flexipos_pin_hash"
DEVICE_ID_FIELD = "flexipos_device_id"
# Freeform (not a Select) since the sensible role set differs per business
# type (Chef/Waiter for a restaurant, Pharmacist/Cashier for a pharmacy,
# etc.) — see the Team & Roles screen's per-niche default suggestions.
ROLE_FIELD = "flexipos_role"
SCREEN_PERMISSIONS_FIELD = "flexipos_screen_permissions"
ALL_SCREEN_PERMISSIONS = {
    "quick_sale", "dashboard", "held_orders", "order_history", "inventory",
    "tables", "kitchen", "shift", "reports", "staff", "settings",
}
ADMIN_ROLE = "Admin"
# Item is a GLOBAL master in ERPNext (no company column), so FlexiPOS
# stamps every item with its owning company and filters all reads on it.
COMPANY_FIELD = "flexipos_company"
# Modifiers (e.g. "Size: Small/Medium/Large", "Add-ons: Extra Cheese +150")
# live in the FlexiPOS Modifier master, composed into groups via
# FlexiPOS Modifier Option link rows (one master, many groups), and
# reused across items via the Item.flexipos_modifier_groups child
# table. A chosen modifier has no item_code of its own — its price is
# folded into the Sales Invoice line's rate and its label appended to
# the line's description.
MODIFIER_GROUPS_FIELD = "flexipos_modifier_groups"
# Stock ERPNext Item Group has no dependable image field, so category
# photos live in our own Attach Image custom field.
CATEGORY_IMAGE_FIELD = "flexipos_image"
# Item Groups are shared ERPNext masters, so writable category images cannot
# live on Item Group without allowing one tenant to overwrite another's image.
# Store the category-name -> file URL mapping on Company instead.
CATEGORY_IMAGES_FIELD = "flexipos_category_images"
CATEGORY_NAMES_FIELD = "flexipos_categories"
DEFAULT_TAX_RATE_FIELD = "flexipos_default_tax_rate"
SERVICE_STYLES_FIELD = "flexipos_service_styles"
BRANCH_COMPANY_FIELD = "flexipos_company"
# Niche-specific item flags/badges — cosmetic in the POS UI, but real
# per-item data (not hardcoded), so a business can turn them on/off per
# product like any other field.
RX_FIELD = "flexipos_requires_prescription"
COLD_CHAIN_FIELD = "flexipos_cold_chain"
DURATION_FIELD = "flexipos_duration_minutes"
# Clothing niche. Material/season/gender are plain labels; the variant
# matrix is one JSON blob per item:
#   {"colours": [{"name": "Olive", "hex": "#6B7C3F"}, ...],
#    "sizes": ["S", "M", "L", "XL"],
#    "qty": {"Olive": {"S": 8, "M": 14, ...}, ...}}
# Kept on the template item (no per-variant Item rows) because FlexiPOS
# items default to is_stock_item=0 — there is no stock ledger to feed.
# The POS variant picker reads colours/sizes straight from this blob.
MATERIAL_FIELD = "flexipos_material"
SEASON_FIELD = "flexipos_season"
GENDER_FIELD = "flexipos_gender"
VARIANT_MATRIX_FIELD = "flexipos_variant_matrix"
GENDER_OPTIONS = ["Men", "Women", "Unisex", "Kids"]
# Item tax percentage. FlexiPOS selling prices are tax-inclusive; invoice
# creation resolves this value from the server and creates the matching
# inclusive Sales Taxes and Charges row.
TAX_RATE_FIELD = "flexipos_tax_rate"
# Simple on-hand count typed by the merchant. NOT ledger stock — items
# stay is_stock_item=0, same reasoning as the clothing variant matrix.
STOCK_QTY_FIELD = "flexipos_stock_qty"
# Restaurant: CSV of dietary badges ("Halal,Gluten-free") and whether the
# dish should eventually deplete ingredient stock via a recipe/BOM (the
# flag is persisted now; BOM consumption is future work).
DIETARY_FIELD = "flexipos_dietary_flags"
RECIPE_DEPLETION_FIELD = "flexipos_recipe_depletion"
GENERIC_NAME_FIELD = "flexipos_generic_name"
BRAND_NAME_FIELD = "flexipos_brand_name"
BATCH_NO_FIELD = "flexipos_batch_no"
EXPIRY_DATE_FIELD = "flexipos_expiry_date"
DOSAGE_FORM_FIELD = "flexipos_dosage_form"
RACK_BIN_FIELD = "flexipos_rack_bin"
REORDER_POINT_FIELD = "flexipos_reorder_point"
DEPARTMENT_FIELD = "flexipos_department"
SHELF_LOCATION_FIELD = "flexipos_shelf_location"
SUPPLIER_FIELD = "flexipos_supplier"
PACK_SIZE_FIELD = "flexipos_pack_size"
REORDER_QTY_FIELD = "flexipos_reorder_qty"
LOW_STOCK_ALERT_FIELD = "flexipos_low_stock_alert"
SHELF_LIFE_FIELD = "flexipos_shelf_life"
LEAD_TIME_FIELD = "flexipos_lead_time"
ALLERGENS_FIELD = "flexipos_allergens"
DEFAULT_SIZE_FIELD = "flexipos_default_size"
ALLOW_CUSTOM_MESSAGE_FIELD = "flexipos_allow_custom_message"
MADE_TO_ORDER_FIELD = "flexipos_made_to_order"
DIETARY_OPTIONS = ["Halal", "Vegetarian", "Vegan", "Gluten-free", "Nut-free", "Spicy"]

ALLOWED_IMAGE_EXTENSIONS = ("jpg", "jpeg", "png", "webp")
MAX_IMAGE_BYTES = 3 * 1024 * 1024

# Batches larger than this are pushed to a background worker; the client
# re-syncs later and the duplicate check below makes retries safe.
INLINE_BATCH_LIMIT = 25
PRICE_TOLERANCE = 0.01
TAX_RATE_TOLERANCE = 0.0001

MAX_PIN_ATTEMPTS = 5
PIN_LOCKOUT_SECONDS = 300

OTP_DOCTYPE = "FlexiPOS OTP"
OTP_TTL_SECONDS = 600
MAX_OTP_REQUESTS = 3  # per email per 15 minutes
MAX_OTP_ATTEMPTS = 5  # wrong codes per email per 10 minutes

# SaaS account lifecycle.  Payment gateways are intentionally not coupled to
# these values: PayFast, bank transfer, Easypaisa/JazzCash, or a card gateway
# can all drive the same state through the signed billing webhook below.
SUBSCRIPTION_STATUS_FIELD = "flexipos_subscription_status"
TRIAL_ENDS_FIELD = "flexipos_trial_ends_on"
CURRENT_PERIOD_END_FIELD = "flexipos_current_period_end"
BILLING_PROVIDER_FIELD = "flexipos_billing_provider"
BILLING_CUSTOMER_FIELD = "flexipos_billing_customer_token"
BILLING_PLAN_FIELD = "flexipos_billing_plan"
BILLING_EMAIL_FIELD = "flexipos_billing_email"
BILLING_EVENT_FIELD = "flexipos_billing_last_event_id"
DELETION_REQUESTED_FIELD = "flexipos_deletion_requested_at"
RETENTION_UNTIL_FIELD = "flexipos_retention_until"
PRIVACY_CONSENT_FIELD = "flexipos_privacy_consent_at"
SUBSCRIPTION_STATUSES = ["Trialing", "Active", "Past Due", "Suspended", "Cancelled", "Archived"]
DEFAULT_TRIAL_DAYS = 7
DEFAULT_RETENTION_DAYS = 30
OPERATIONAL_SUBSCRIPTION_STATUSES = {"Trialing", "Active"}
DEFAULT_TRIAL_DAYS_KEY = "flexipos_default_trial_days"
MAX_TRIAL_EXTENSION_DAYS = 365
SAAS_SETTINGS_DOCTYPE = "FlexiPOS SaaS Settings"


# ---------------------------------------------------------------------------
# Installation helper
# ---------------------------------------------------------------------------

def setup_custom_fields():
    """Create the Custom Fields FlexiPOS relies on. Idempotent."""
    from frappe.custom.doctype.custom_field.custom_field import create_custom_fields

    create_custom_fields(
        {
            "Sales Invoice": [
                {
                    "fieldname": OFFLINE_ID_FIELD,
                    "label": "FlexiPOS Offline ID",
                    "fieldtype": "Data",
                    "unique": 1,
                    "read_only": 1,
                    "no_copy": 1,
                    "insert_after": "naming_series",
                },
                {
                    "fieldname": ORDER_TYPE_FIELD,
                    "label": "FlexiPOS Order Type",
                    "fieldtype": "Select",
                    "options": "\nDine-in\nTakeaway\nDelivery",
                    "read_only": 1,
                    "no_copy": 1,
                    "insert_after": OFFLINE_ID_FIELD,
                },
                {
                    "fieldname": TABLE_FIELD,
                    "label": "FlexiPOS Table No",
                    "fieldtype": "Data",
                    "read_only": 1,
                    "no_copy": 1,
                    "insert_after": ORDER_TYPE_FIELD,
                },
                {
                    "fieldname": KITCHEN_STATUS_FIELD,
                    "label": "FlexiPOS Kitchen Status",
                    "fieldtype": "Select",
                    "options": "\n" + "\n".join(KITCHEN_STATUSES),
                    "no_copy": 1,
                    "insert_after": TABLE_FIELD,
                },
                {
                    "fieldname": REGISTER_ID_FIELD,
                    "label": "FlexiPOS Register ID",
                    "fieldtype": "Data",
                    "read_only": 1,
                    "no_copy": 1,
                    "search_index": 1,
                    "insert_after": KITCHEN_STATUS_FIELD,
                },
            ],
            "Company": [
                {
                    "fieldname": "flexipos_business_type",
                    "label": "FlexiPOS Business Type",
                    "fieldtype": "Select",
                    "options": "\n" + "\n".join(BUSINESS_TYPES),
                    "insert_after": "company_description",
                },
                {
                    "fieldname": "flexipos_phone",
                    "label": "FlexiPOS Phone",
                    "fieldtype": "Data",
                    "insert_after": "flexipos_business_type",
                },
                {
                    "fieldname": CATEGORY_IMAGES_FIELD,
                    "label": "FlexiPOS Category Images (JSON)",
                    "fieldtype": "Long Text",
                    "hidden": 1,
                    "no_copy": 1,
                    "insert_after": "flexipos_phone",
                },
                {
                    "fieldname": CATEGORY_NAMES_FIELD,
                    "label": "FlexiPOS Categories (JSON)",
                    "fieldtype": "Long Text",
                    "hidden": 1,
                    "no_copy": 1,
                    "insert_after": CATEGORY_IMAGES_FIELD,
                },
                {
                    "fieldname": DEFAULT_TAX_RATE_FIELD,
                    "label": "FlexiPOS Default Tax Rate",
                    "fieldtype": "Percent",
                    "insert_after": CATEGORY_NAMES_FIELD,
                },
                {
                    "fieldname": SERVICE_STYLES_FIELD,
                    "label": "FlexiPOS Service Styles",
                    "fieldtype": "Data",
                    "insert_after": DEFAULT_TAX_RATE_FIELD,
                },
                {
                    "fieldname": SUBSCRIPTION_STATUS_FIELD,
                    "label": "FlexiPOS Subscription Status",
                    "fieldtype": "Select",
                    "options": "\n" + "\n".join(SUBSCRIPTION_STATUSES),
                    "default": "Active",
                    "read_only": 1,
                    "search_index": 1,
                    "insert_after": SERVICE_STYLES_FIELD,
                },
                {
                    "fieldname": TRIAL_ENDS_FIELD,
                    "label": "FlexiPOS Trial Ends On",
                    "fieldtype": "Datetime",
                    "read_only": 1,
                    "insert_after": SUBSCRIPTION_STATUS_FIELD,
                },
                {
                    "fieldname": CURRENT_PERIOD_END_FIELD,
                    "label": "FlexiPOS Current Period End",
                    "fieldtype": "Datetime",
                    "read_only": 1,
                    "insert_after": TRIAL_ENDS_FIELD,
                },
                {
                    "fieldname": BILLING_PROVIDER_FIELD,
                    "label": "FlexiPOS Billing Provider",
                    "fieldtype": "Data",
                    "insert_after": CURRENT_PERIOD_END_FIELD,
                },
                {
                    "fieldname": BILLING_CUSTOMER_FIELD,
                    "label": "FlexiPOS Billing Customer Token",
                    "fieldtype": "Data",
                    "hidden": 1,
                    "no_copy": 1,
                    "insert_after": BILLING_PROVIDER_FIELD,
                },
                {
                    "fieldname": BILLING_PLAN_FIELD,
                    "label": "FlexiPOS Billing Plan",
                    "fieldtype": "Data",
                    "insert_after": BILLING_CUSTOMER_FIELD,
                },
                {
                    "fieldname": BILLING_EMAIL_FIELD,
                    "label": "FlexiPOS Billing Email",
                    "fieldtype": "Data",
                    "insert_after": BILLING_PLAN_FIELD,
                },
                {
                    "fieldname": BILLING_EVENT_FIELD,
                    "label": "FlexiPOS Last Billing Event ID",
                    "fieldtype": "Data",
                    "hidden": 1,
                    "no_copy": 1,
                    "insert_after": BILLING_EMAIL_FIELD,
                },
                {
                    "fieldname": DELETION_REQUESTED_FIELD,
                    "label": "FlexiPOS Deletion Requested At",
                    "fieldtype": "Datetime",
                    "hidden": 1,
                    "no_copy": 1,
                    "insert_after": BILLING_EVENT_FIELD,
                },
                {
                    "fieldname": RETENTION_UNTIL_FIELD,
                    "label": "FlexiPOS Retention Until",
                    "fieldtype": "Date",
                    "hidden": 1,
                    "no_copy": 1,
                    "insert_after": DELETION_REQUESTED_FIELD,
                },
                {
                    "fieldname": PRIVACY_CONSENT_FIELD,
                    "label": "FlexiPOS Privacy Consent At",
                    "fieldtype": "Datetime",
                    "hidden": 1,
                    "no_copy": 1,
                    "insert_after": RETENTION_UNTIL_FIELD,
                },
            ],
            "Branch": [
                {
                    "fieldname": BRANCH_COMPANY_FIELD,
                    "label": "FlexiPOS Company",
                    "fieldtype": "Link",
                    "options": "Company",
                    "read_only": 1,
                    "no_copy": 1,
                    "search_index": 1,
                    "insert_after": "branch",
                }
            ],
            "Item": [
                {
                    "fieldname": COMPANY_FIELD,
                    "label": "FlexiPOS Company",
                    "fieldtype": "Link",
                    "options": "Company",
                    "read_only": 1,
                    "no_copy": 1,
                    "search_index": 1,
                    "insert_after": "item_group",
                },
                {
                    "fieldname": MODIFIER_GROUPS_FIELD,
                    "label": "FlexiPOS Modifier Groups",
                    "fieldtype": "Table",
                    "options": "FlexiPOS Item Modifier Group",
                    "insert_after": COMPANY_FIELD,
                },
                {
                    "fieldname": RX_FIELD,
                    "label": "Requires Prescription",
                    "fieldtype": "Check",
                    "default": "0",
                    "insert_after": MODIFIER_GROUPS_FIELD,
                },
                {
                    "fieldname": COLD_CHAIN_FIELD,
                    "label": "Cold Chain",
                    "fieldtype": "Check",
                    "default": "0",
                    "insert_after": RX_FIELD,
                },
                {
                    "fieldname": DURATION_FIELD,
                    "label": "Duration (Minutes)",
                    "fieldtype": "Int",
                    "insert_after": COLD_CHAIN_FIELD,
                },
                {
                    "fieldname": MATERIAL_FIELD,
                    "label": "Material",
                    "fieldtype": "Data",
                    "insert_after": DURATION_FIELD,
                },
                {
                    "fieldname": SEASON_FIELD,
                    "label": "Season",
                    "fieldtype": "Data",
                    "insert_after": MATERIAL_FIELD,
                },
                {
                    "fieldname": GENDER_FIELD,
                    "label": "Gender",
                    "fieldtype": "Select",
                    "options": "\n" + "\n".join(GENDER_OPTIONS),
                    "insert_after": SEASON_FIELD,
                },
                {
                    "fieldname": VARIANT_MATRIX_FIELD,
                    "label": "Variant Matrix (JSON)",
                    "fieldtype": "Long Text",
                    "hidden": 1,
                    "insert_after": GENDER_FIELD,
                },
                {
                    "fieldname": TAX_RATE_FIELD,
                    "label": "Tax Rate (%)",
                    "fieldtype": "Percent",
                    "insert_after": VARIANT_MATRIX_FIELD,
                },
                {
                    "fieldname": STOCK_QTY_FIELD,
                    "label": "Stock Qty (simple count)",
                    "fieldtype": "Int",
                    "insert_after": TAX_RATE_FIELD,
                },
                {
                    "fieldname": DIETARY_FIELD,
                    "label": "Dietary Flags",
                    "fieldtype": "Data",
                    "insert_after": STOCK_QTY_FIELD,
                },
                {
                    "fieldname": RECIPE_DEPLETION_FIELD,
                    "label": "Recipe-based Depletion",
                    "fieldtype": "Check",
                    "default": "0",
                    "insert_after": DIETARY_FIELD,
                },
                {"fieldname": GENERIC_NAME_FIELD, "label": "Generic Name", "fieldtype": "Data", "insert_after": RECIPE_DEPLETION_FIELD},
                {"fieldname": BRAND_NAME_FIELD, "label": "Brand Name", "fieldtype": "Data", "insert_after": GENERIC_NAME_FIELD},
                {"fieldname": BATCH_NO_FIELD, "label": "Batch / Lot No.", "fieldtype": "Data", "insert_after": BRAND_NAME_FIELD},
                {"fieldname": EXPIRY_DATE_FIELD, "label": "Expiry Date", "fieldtype": "Data", "insert_after": BATCH_NO_FIELD},
                {"fieldname": DOSAGE_FORM_FIELD, "label": "Dosage Form", "fieldtype": "Data", "insert_after": EXPIRY_DATE_FIELD},
                {"fieldname": RACK_BIN_FIELD, "label": "Rack / Bin", "fieldtype": "Data", "insert_after": DOSAGE_FORM_FIELD},
                {"fieldname": REORDER_POINT_FIELD, "label": "Reorder Point", "fieldtype": "Int", "insert_after": RACK_BIN_FIELD},
                {"fieldname": DEPARTMENT_FIELD, "label": "Department", "fieldtype": "Data", "insert_after": REORDER_POINT_FIELD},
                {"fieldname": SHELF_LOCATION_FIELD, "label": "Shelf Location", "fieldtype": "Data", "insert_after": DEPARTMENT_FIELD},
                {"fieldname": SUPPLIER_FIELD, "label": "Supplier", "fieldtype": "Data", "insert_after": SHELF_LOCATION_FIELD},
                {"fieldname": PACK_SIZE_FIELD, "label": "Pack / Case Size", "fieldtype": "Data", "insert_after": SUPPLIER_FIELD},
                {"fieldname": REORDER_QTY_FIELD, "label": "Reorder Qty", "fieldtype": "Int", "insert_after": PACK_SIZE_FIELD},
                {"fieldname": LOW_STOCK_ALERT_FIELD, "label": "Low-stock Alert", "fieldtype": "Check", "default": "0", "insert_after": REORDER_QTY_FIELD},
                {"fieldname": SHELF_LIFE_FIELD, "label": "Shelf Life", "fieldtype": "Data", "insert_after": LOW_STOCK_ALERT_FIELD},
                {"fieldname": LEAD_TIME_FIELD, "label": "Lead Time", "fieldtype": "Data", "insert_after": SHELF_LIFE_FIELD},
                {"fieldname": ALLERGENS_FIELD, "label": "Allergens", "fieldtype": "Data", "insert_after": LEAD_TIME_FIELD},
                {"fieldname": DEFAULT_SIZE_FIELD, "label": "Default Size", "fieldtype": "Data", "insert_after": ALLERGENS_FIELD},
                {"fieldname": ALLOW_CUSTOM_MESSAGE_FIELD, "label": "Allow Custom Message", "fieldtype": "Check", "default": "0", "insert_after": DEFAULT_SIZE_FIELD},
                {"fieldname": MADE_TO_ORDER_FIELD, "label": "Made to Order", "fieldtype": "Check", "default": "0", "insert_after": ALLOW_CUSTOM_MESSAGE_FIELD},
            ],
            "Item Group": [
                {
                    "fieldname": CATEGORY_IMAGE_FIELD,
                    "label": "FlexiPOS Image",
                    "fieldtype": "Attach Image",
                    "insert_after": "is_group",
                }
            ],
            "User": [
                {
                    "fieldname": PIN_HASH_FIELD,
                    "label": "FlexiPOS PIN Hash",
                    "fieldtype": "Password",
                    "hidden": 1,
                    "no_copy": 1,
                    "insert_after": "new_password",
                },
                {
                    "fieldname": DEVICE_ID_FIELD,
                    "label": "FlexiPOS Device ID",
                    "fieldtype": "Data",
                    "no_copy": 1,
                    "insert_after": PIN_HASH_FIELD,
                },
                {
                    "fieldname": ROLE_FIELD,
                    "label": "FlexiPOS Role",
                    "fieldtype": "Data",
                    "no_copy": 1,
                    "insert_after": DEVICE_ID_FIELD,
                },
                {
                    "fieldname": SCREEN_PERMISSIONS_FIELD,
                    "label": "FlexiPOS Screen Permissions",
                    "fieldtype": "Long Text",
                    "hidden": 1,
                    "no_copy": 1,
                    "insert_after": ROLE_FIELD,
                },
            ],
        },
        ignore_validate=True,
    )

    # create_custom_fields skips fields that already exist, so enforce the
    # current business-type options on sites installed before a change.
    frappe.db.set_value(
        "Custom Field",
        {"dt": "Company", "fieldname": "flexipos_business_type"},
        "options",
        "\n" + "\n".join(BUSINESS_TYPES),
        update_modified=False,
    )

    # Backfill the deterministic main branches created by older FlexiPOS
    # versions. Never overwrite an existing owner stamp.
    for company in frappe.get_all("Company", fields=["name"], limit_page_length=0):
        branch_name = f"{company.name} - Main"
        if frappe.db.exists("Branch", branch_name) and not frappe.db.get_value(
            "Branch", branch_name, BRANCH_COMPANY_FIELD
        ):
            frappe.db.set_value(
                "Branch",
                branch_name,
                BRANCH_COMPANY_FIELD,
                company.name,
                update_modified=False,
            )


def _ensure_custom_fields():
    """Create the custom fields on first use if the site hasn't been
    migrated yet. Custom Field writes need admin rights, and the caller
    may be Guest (self-serve signup) — so elevate just for this step."""
    # These sentinels cover each DocType touched by the setup routine.
    required_fields = (
        ("Item", MADE_TO_ORDER_FIELD),
        ("User", SCREEN_PERMISSIONS_FIELD),
        ("Company", SERVICE_STYLES_FIELD),
        ("Company", SUBSCRIPTION_STATUS_FIELD),
        ("Branch", BRANCH_COMPANY_FIELD),
    )
    if all(
        frappe.db.exists(
            "Custom Field", {"dt": doctype, "fieldname": fieldname}
        )
        for doctype, fieldname in required_fields
    ):
        return
    original_user = frappe.session.user
    frappe.set_user("Administrator")
    try:
        setup_custom_fields()
    finally:
        frappe.set_user(original_user)


# ---------------------------------------------------------------------------
# 1. setup_new_business
# ---------------------------------------------------------------------------

@frappe.whitelist(allow_guest=True)
def register_business(business_name, business_type, phone=None, email=None):
    """Self-serve signup used by the app's onboarding screen.

    Creates the User account (no password — this device authenticates via
    PIN afterwards), logs them in, and runs the full business setup.
    Returns the setup payload plus the new session sid.
    """
    business_name = (business_name or "").strip()
    email = (email or "").strip().lower()
    phone = (phone or "").strip()

    if not business_name:
        frappe.throw(_("Business name is required"))
    validate_email_address(email, throw=True)
    if business_type not in BUSINESS_TYPES:
        business_type = "Retail"

    _rate_limit_signup()

    if frappe.db.exists("User", email):
        frappe.throw(
            _("An account with {0} already exists. Please log in instead.").format(
                email
            )
        )
    if frappe.db.exists("Company", {"company_name": business_name}):
        frappe.throw(_("A business named {0} already exists").format(business_name))

    _ensure_custom_fields()

    try:
        user = frappe.get_doc(
            {
                "doctype": "User",
                "email": email,
                "first_name": business_name,
                "mobile_no": phone,
                "user_type": "System User",
                "send_welcome_email": 0,
            }
        )
        user.flags.no_welcome_mail = True
        user.insert(ignore_permissions=True)

        # Switch request context to the new user (no session yet — a
        # session commits the transaction, which would strand a half-made
        # account if a later step failed).
        frappe.set_user(email)
        result = _setup_business(business_name, business_type, phone)
        credentials = _get_api_credentials(email)

        # Everything worked — only now open the real session.
        frappe.local.login_manager.login_as(email)
        frappe.db.commit()
    except Exception:
        frappe.db.rollback()
        frappe.set_user("Guest")
        frappe.log_error(frappe.get_traceback(), "FlexiPOS: register_business failed")
        frappe.throw(_("Could not create your account. The error has been logged."))

    result.update({"user": email, "sid": frappe.session.sid, **credentials})
    return result


def _require_business_setup_access():
    """Only an authenticated account with no existing tenant may onboard."""
    user = frappe.session.user
    if not user or user == "Guest":
        frappe.throw(_("Login required"), frappe.AuthenticationError)
    already_linked = frappe.db.exists(
        "User Permission", {"user": user, "allow": "Company"}
    ) or frappe.db.exists(
        "POS Profile User", {"user": user, "parenttype": "POS Profile"}
    )
    if already_linked:
        frappe.throw(
            _("This account is already linked to a business"),
            frappe.PermissionError,
        )


@frappe.whitelist()
def setup_new_business(company_name, business_type=None, phone=None):
    """Create Company + default Branch + POS Profile for an already
    logged-in user. Returns the names of everything created."""
    company_name = (company_name or "").strip()
    if not company_name:
        frappe.throw(_("Business name is required"))
    _require_business_setup_access()
    if frappe.db.exists("Company", {"company_name": company_name}):
        frappe.throw(_("A business named {0} already exists").format(company_name))

    _ensure_custom_fields()

    try:
        result = _setup_business(company_name, business_type, phone)
        frappe.db.commit()
    except Exception:
        frappe.db.rollback()
        frappe.log_error(frappe.get_traceback(), "FlexiPOS: setup_new_business failed")
        frappe.throw(
            _("Could not set up the business. The error has been logged.")
        )
    return result


@frappe.whitelist()
def get_my_business():
    """Return the business bound to the logged-in user, for the
    "already have an account" login flow on a new device."""
    user = frappe.session.user
    if user == "Guest":
        frappe.throw(_("Login required"), frappe.AuthenticationError)
    company = _get_user_company()
    profile = _get_pos_profile_for_company(None, company, user)
    business_type = frappe.db.get_value(
        "Company", profile.company, "flexipos_business_type"
    )
    role = _effective_role(user)
    screen_permissions = _screen_permissions_for_user(user, role)
    config = _get_business_config(company)
    subscription = _subscription_payload(company)
    return {
        "company": company,
        "business_type": business_type,
        "role": role,
        "screen_permissions": screen_permissions,
        "pos_profile": profile.name,
        "customer": profile.customer,
        "currency": profile.currency,
        "warehouse": profile.warehouse,
        "price_list": profile.selling_price_list,
        **config,
        "subscription": subscription,
        **_subscription_client_payload(company),
    }


def _subscription_payload(company):
    """Return safe subscription metadata (never card/PAN or gateway secrets)."""
    values = frappe.db.get_value(
        "Company",
        company,
        [SUBSCRIPTION_STATUS_FIELD, TRIAL_ENDS_FIELD, CURRENT_PERIOD_END_FIELD,
         BILLING_PROVIDER_FIELD, BILLING_PLAN_FIELD, BILLING_EMAIL_FIELD,
         DELETION_REQUESTED_FIELD, RETENTION_UNTIL_FIELD],
        as_dict=True,
    ) or {}
    status = values.get(SUBSCRIPTION_STATUS_FIELD) or "Active"
    now = now_datetime()
    trial_end = values.get(TRIAL_ENDS_FIELD)
    period_end = values.get(CURRENT_PERIOD_END_FIELD)
    saas_settings = _get_saas_settings()
    require_billing_setup = cint(saas_settings.require_payment_method_on_signup)
    has_payment_token = bool(frappe.db.get_value("Company", company, BILLING_CUSTOMER_FIELD))
    if status == "Trialing" and trial_end and get_datetime(trial_end) <= now:
        status = "Past Due"
        frappe.db.set_value("Company", company, SUBSCRIPTION_STATUS_FIELD, status, update_modified=False)
    elif status == "Active" and period_end and get_datetime(period_end) <= now:
        status = "Past Due"
        frappe.db.set_value("Company", company, SUBSCRIPTION_STATUS_FIELD, status, update_modified=False)
    return {
        "status": status,
        "trial_ends_on": str(trial_end) if trial_end else None,
        "current_period_end": str(period_end) if period_end else None,
        "billing_provider": values.get(BILLING_PROVIDER_FIELD)
        or (saas_settings.billing_provider if saas_settings.billing_enabled else None),
        "plan": values.get(BILLING_PLAN_FIELD) or None,
        "billing_email": values.get(BILLING_EMAIL_FIELD) or None,
        "deletion_requested_at": str(values.get(DELETION_REQUESTED_FIELD)) if values.get(DELETION_REQUESTED_FIELD) else None,
        "retention_until": str(values.get(RETENTION_UNTIL_FIELD)) if values.get(RETENTION_UNTIL_FIELD) else None,
        "trial_days": _default_trial_days(),
        "billing_setup_required": bool(require_billing_setup and not has_payment_token),
        "terms_url": saas_settings.terms_url or None,
        "privacy_url": saas_settings.privacy_url or None,
    }


def _default_trial_days():
    """Site-wide trial length for future tenants, bounded defensively."""
    settings = _get_saas_settings()
    configured = settings.default_trial_days
    if configured in (None, ""):
        configured = frappe.db.get_default(DEFAULT_TRIAL_DAYS_KEY)
    days = DEFAULT_TRIAL_DAYS if configured in (None, "") else cint(configured)
    return max(0, min(days, 90))


def _get_saas_settings(include_secrets=False):
    """Return the site-wide billing configuration with safe legacy fallbacks.

    Tenant-facing callers never request secrets. Password values are decrypted
    only for server-side provider/webhook operations.
    """
    values = frappe._dict(
        billing_enabled=bool(frappe.conf.get("flexipos_billing_enabled")),
        billing_provider=frappe.conf.get("flexipos_billing_provider") or "Safepay",
        sandbox_mode=bool(frappe.conf.get("flexipos_billing_sandbox", True)),
        require_payment_method_on_signup=bool(
            frappe.conf.get("flexipos_require_card_on_signup")
        ),
        public_api_key=frappe.conf.get("flexipos_billing_public_key"),
        checkout_url=frappe.conf.get("flexipos_billing_checkout_url"),
        default_plan="monthly",
        monthly_plan_id=None,
        annual_plan_id=None,
        default_trial_days=frappe.db.get_default(DEFAULT_TRIAL_DAYS_KEY),
        deletion_retention_days=DEFAULT_RETENTION_DAYS,
        terms_url=None,
        privacy_url=None,
    )
    if frappe.db.exists("DocType", SAAS_SETTINGS_DOCTYPE):
        doc = frappe.get_single(SAAS_SETTINGS_DOCTYPE)
        for fieldname in values:
            value = doc.get(fieldname)
            if value not in (None, ""):
                values[fieldname] = value
        if include_secrets:
            values.secret_api_key = doc.get_password(
                "secret_api_key", raise_exception=False
            ) or frappe.conf.get("flexipos_billing_secret_key")
            values.webhook_secret = doc.get_password(
                "webhook_secret", raise_exception=False
            ) or frappe.conf.get("flexipos_billing_webhook_secret")
    elif include_secrets:
        values.secret_api_key = frappe.conf.get("flexipos_billing_secret_key")
        values.webhook_secret = frappe.conf.get("flexipos_billing_webhook_secret")
    return values


def _default_deletion_retention_days():
    configured = cint(_get_saas_settings().deletion_retention_days)
    return max(1, min(configured or DEFAULT_RETENTION_DAYS, 3650))


def _subscription_client_payload(company):
    """Stable flattened contract consumed by Flutter login/session flows."""
    value = _subscription_payload(company)
    status_key = value["status"].lower().replace(" ", "_")
    tenant_status = "suspended" if value["status"] == "Suspended" else (
        "archived" if value["status"] == "Archived" else "active"
    )
    return {
        "subscription_status": status_key,
        "subscription_plan": value.get("plan"),
        "billing_provider": value.get("billing_provider"),
        "trial_ends_at": value.get("trial_ends_on"),
        "subscription_ends_at": value.get("current_period_end"),
        "tenant_status": tenant_status,
        "billing_setup_required": value.get("billing_setup_required", False),
    }


def _require_subscription_access(company=None):
    """Block business mutations/reads after trial or billing expiry.

    Legacy companies with no lifecycle field are treated as Active so a
    migration cannot unexpectedly lock an existing merchant out.
    """
    company = company or _get_user_company()
    subscription = _subscription_payload(company)
    if subscription["status"] not in OPERATIONAL_SUBSCRIPTION_STATUSES:
        frappe.throw(
            _("This business subscription is {0}. Update billing to continue.").format(subscription["status"]),
            frappe.PermissionError,
        )
    return subscription


@frappe.whitelist()
def get_subscription():
    """Return the current tenant lifecycle state for the billing screen."""
    if frappe.session.user == "Guest":
        frappe.throw(_("Login required"), frappe.AuthenticationError)
    company = _get_user_company()
    subscription = _subscription_payload(company)
    return {
        "company": company,
        "subscription": subscription,
        **_subscription_client_payload(company),
    }


@frappe.whitelist()
def get_subscription_status():
    """Compatibility name used by the billing UI."""
    return get_subscription()


def _require_saas_operator():
    """Reserve cross-tenant controls for the Frappe site Administrator."""
    if frappe.session.user != "Administrator":
        frappe.throw(_("Only the SaaS operator can manage tenant lifecycle"), frappe.PermissionError)


def _audit_saas_action(action, company=None, details=None):
    """Write an operator audit record without payment credentials or PII."""
    try:
        frappe.get_doc(
            {
                "doctype": "Activity Log",
                "subject": f"FlexiPOS SaaS: {action}"[:140],
                "status": "Success",
                "user": frappe.session.user,
                "reference_doctype": "Company" if company else None,
                "reference_name": company,
                "full_name": frappe.session.user,
                "ip_address": getattr(frappe.local, "request_ip", None),
                "timeline_doctype": "Company" if company else None,
                "timeline_name": company,
                "content": json.dumps(details or {}, default=str),
            }
        ).insert(ignore_permissions=True)
    except Exception:
        # Lifecycle state changes must not fail merely because a site has a
        # customised Activity Log schema. Keep a server-side error trail.
        frappe.log_error(frappe.get_traceback(), "FlexiPOS SaaS audit failed")


@frappe.whitelist()
def saas_list_tenants(limit=200, start=0):
    """Cross-tenant operational view for the site Administrator."""
    _require_saas_operator()
    limit = max(1, min(cint(limit), 500))
    start = max(0, cint(start))
    rows = frappe.get_all(
        "Company",
        fields=["name", "company_name", SUBSCRIPTION_STATUS_FIELD, TRIAL_ENDS_FIELD,
                CURRENT_PERIOD_END_FIELD, BILLING_PROVIDER_FIELD, BILLING_PLAN_FIELD,
                DELETION_REQUESTED_FIELD, RETENTION_UNTIL_FIELD],
        order_by="creation desc",
        limit_start=start,
        limit_page_length=limit,
    )
    return {
        "tenants": [
            {"company": row.name, "company_name": row.company_name, **_subscription_payload(row.name)}
            for row in rows
        ],
        "default_trial_days": _default_trial_days(),
        "start": start,
        "limit": limit,
    }


@frappe.whitelist()
def saas_set_default_trial_days(days):
    """Change the default trial length for businesses created afterwards."""
    _require_saas_operator()
    days = cint(days)
    if days < 0 or days > 90:
        frappe.throw(_("Default trial days must be between 0 and 90"))
    if frappe.db.exists("DocType", SAAS_SETTINGS_DOCTYPE):
        settings = frappe.get_single(SAAS_SETTINGS_DOCTYPE)
        settings.default_trial_days = days
        settings.save(ignore_permissions=True)
    else:
        frappe.db.set_default(DEFAULT_TRIAL_DAYS_KEY, days)
    _audit_saas_action("default trial changed", details={"days": days})
    return {"default_trial_days": days}


@frappe.whitelist()
def saas_extend_trial(days, company=None, all_companies=0):
    """Extend one tenant or every eligible tenant from its current end date.

    This is deliberately additive: extending an unexpired 7-day trial by 3
    days produces 10 total days. Expired trials restart from the current UTC
    time. Archived/deletion-pending tenants are never revived in bulk.
    """
    _require_saas_operator()
    days = cint(days)
    if days < 1 or days > MAX_TRIAL_EXTENSION_DAYS:
        frappe.throw(_("Trial extension must be between 1 and {0} days").format(MAX_TRIAL_EXTENSION_DAYS))
    if cint(all_companies):
        companies = frappe.get_all(
            "Company",
            filters={SUBSCRIPTION_STATUS_FIELD: ("in", ["Trialing", "Past Due", "Cancelled"])},
            pluck="name",
            limit_page_length=0,
        )
    else:
        company = (company or "").strip()
        if not company or not frappe.db.exists("Company", company):
            frappe.throw(_("A valid company is required"))
        if frappe.db.get_value("Company", company, SUBSCRIPTION_STATUS_FIELD) == "Archived":
            frappe.throw(_("Archived tenants cannot receive a trial extension"), frappe.PermissionError)
        if frappe.db.get_value("Company", company, DELETION_REQUESTED_FIELD):
            frappe.throw(_("Cancel the deletion request before extending this trial"), frappe.PermissionError)
        companies = [company]

    now = now_datetime()
    updated = []
    for name in companies:
        if frappe.db.get_value("Company", name, DELETION_REQUESTED_FIELD):
            continue
        current_end = frappe.db.get_value("Company", name, TRIAL_ENDS_FIELD)
        base = get_datetime(current_end) if current_end and get_datetime(current_end) > now else now
        new_end = add_to_date(base, days=days)
        frappe.db.set_value(
            "Company",
            name,
            {SUBSCRIPTION_STATUS_FIELD: "Trialing", TRIAL_ENDS_FIELD: new_end},
            update_modified=False,
        )
        updated.append({"company": name, "trial_ends_at": str(new_end)})
        if not cint(all_companies):
            _audit_saas_action("trial extended", name, {"days": days, "trial_ends_at": str(new_end)})
    if cint(all_companies):
        _audit_saas_action("bulk trial extension", details={"days": days, "tenant_count": len(updated)})
    return {"updated": updated, "count": len(updated), "days_added": days}


@frappe.whitelist()
def saas_set_tenant_status(company, status, current_period_end=None, reason=None):
    """Suspend, reactivate, cancel, or archive a specific tenant centrally."""
    _require_saas_operator()
    company = (company or "").strip()
    status = (status or "").strip().title()
    if not frappe.db.exists("Company", company):
        frappe.throw(_("Unknown business"), frappe.PermissionError)
    if status not in SUBSCRIPTION_STATUSES:
        frappe.throw(_("Invalid subscription status"))
    values = {SUBSCRIPTION_STATUS_FIELD: status}
    if current_period_end:
        period_end = get_datetime(current_period_end)
        if period_end <= now_datetime():
            frappe.throw(_("The subscription period end must be in the future"))
        values[CURRENT_PERIOD_END_FIELD] = period_end
    elif status == "Active" and not frappe.db.get_value("Company", company, CURRENT_PERIOD_END_FIELD):
        frappe.throw(_("An active tenant needs a future subscription period end"))
    frappe.db.set_value("Company", company, values, update_modified=False)
    _audit_saas_action("tenant status changed", company, {"status": status, "reason": (reason or "")[:240]})
    return {"company": company, "subscription": _subscription_payload(company)}


@frappe.whitelist()
def start_billing_checkout(plan, provider=None, billing_email=None, customer_token=None, privacy_consent=False):
    """Save a provider-neutral billing intent.

    The app must never receive card numbers/CVV. ``customer_token`` is an
    opaque gateway token is accepted only from the gateway's signed webhook.
    The webhook activates the plan after a successful setup/charge; this
    endpoint deliberately does not grant access.
    """
    company = _get_user_company()
    _require_admin(company)
    settings = _get_saas_settings()
    if not cint(settings.billing_enabled):
        frappe.throw(_("Billing is not enabled by the SaaS operator"))
    configured_provider = (settings.billing_provider or "safepay").strip().lower()
    provider = (provider or configured_provider).strip().lower()
    if provider != configured_provider:
        frappe.throw(_("The requested billing provider is not enabled"), frappe.PermissionError)
    plan = (plan or settings.default_plan or "").strip()[:80]
    billing_email = (billing_email or frappe.session.user or "").strip().lower()
    if not provider or not plan:
        frappe.throw(_("Billing provider and plan are required"))
    if billing_email:
        validate_email_address(billing_email, throw=True)
    if not cint(privacy_consent):
        frappe.throw(_("Privacy consent is required before billing"))
    if customer_token:
        frappe.throw(
            _("Payment tokens can only be registered by a verified billing webhook"),
            frappe.PermissionError,
        )
    frappe.db.set_value(
        "Company", company,
        {
            BILLING_PROVIDER_FIELD: provider,
            BILLING_PLAN_FIELD: plan,
            BILLING_EMAIL_FIELD: billing_email,
            # Consent is recorded only after the user explicitly accepts the
            # privacy notice alongside hosted billing checkout.
            PRIVACY_CONSENT_FIELD: now_datetime(),
        },
        update_modified=False,
    )
    return {
        "company": company,
        "provider": provider,
        "plan": plan,
        "status": _subscription_payload(company)["status"],
        "checkout_required": True,
        "checkout_url": settings.checkout_url or None,
        "card_data_storage": "never",
    }


@frappe.whitelist()
def create_billing_checkout(plan, provider=None, billing_email=None, customer_token=None, privacy_consent=False):
    """Compatibility name for clients calling the checkout endpoint."""
    return start_billing_checkout(plan, provider, billing_email, customer_token, privacy_consent)


@frappe.whitelist()
def admin_set_subscription(status, current_period_end=None, plan=None):
    """Manual billing control for PayFast/manual bank settlement operations."""
    company = _get_user_company()
    _require_admin(company)
    status = (status or "").strip().title()
    if status not in SUBSCRIPTION_STATUSES:
        frappe.throw(_("Invalid subscription status"))
    period_end = get_datetime(current_period_end) if current_period_end else None
    if status == "Active" and (not period_end or period_end <= now_datetime()):
        frappe.throw(_("An active subscription needs a future period end"))
    values = {SUBSCRIPTION_STATUS_FIELD: status}
    if period_end:
        values[CURRENT_PERIOD_END_FIELD] = period_end
    if plan is not None:
        values[BILLING_PLAN_FIELD] = str(plan).strip()[:80]
    frappe.db.set_value("Company", company, values, update_modified=False)
    return {"company": company, "subscription": _subscription_payload(company)}


@frappe.whitelist()
def cancel_subscription():
    company = _get_user_company()
    _require_admin(company)
    frappe.db.set_value("Company", company, SUBSCRIPTION_STATUS_FIELD, "Cancelled", update_modified=False)
    return {"company": company, "subscription": _subscription_payload(company)}


def _contains_raw_card_data(value):
    forbidden = {"card_number", "cardnumber", "pan", "cvv", "cvc", "security_code"}
    if isinstance(value, dict):
        return any(
            str(key).lower().replace("-", "_") in forbidden
            or _contains_raw_card_data(child)
            for key, child in value.items()
        )
    if isinstance(value, list):
        return any(_contains_raw_card_data(child) for child in value)
    return False


@frappe.whitelist(allow_guest=True)
def billing_webhook(provider, event_id, event_type, company, status, signature, payload_json="{}"):
    """Consume an idempotent, HMAC-signed gateway event.

    Configure the encrypted webhook secret in FlexiPOS SaaS Settings. The
    canonical JSON payload is signed with HMAC-SHA256. Webhook handlers only
    store opaque customer tokens; raw card data is rejected by design.
    """
    settings = _get_saas_settings(include_secrets=True)
    if not cint(settings.billing_enabled):
        frappe.throw(_("Billing is not enabled"), frappe.PermissionError)
    configured_provider = (settings.billing_provider or "").strip().lower()
    if str(provider or "").strip().lower() != configured_provider:
        frappe.throw(_("Webhook provider does not match SaaS settings"), frappe.PermissionError)
    secret = settings.webhook_secret
    if not secret:
        frappe.throw(_("Billing webhook secret is not configured"), frappe.PermissionError)
    try:
        payload = json.loads(payload_json or "{}")
    except (TypeError, json.JSONDecodeError):
        frappe.throw(_("Invalid billing webhook payload"))
    if not isinstance(payload, dict):
        frappe.throw(_("Invalid billing webhook payload"))
    if _contains_raw_card_data(payload):
        frappe.throw(_("Billing payload must contain tokenised payment data only"), frappe.PermissionError)
    signed_payload = {
        **payload,
        "provider": provider,
        "event_id": event_id,
        "event_type": event_type,
        "company": company,
        "status": status,
    }
    canonical = json.dumps(signed_payload, sort_keys=True, separators=(",", ":"))
    # Safepay signs webhooks with HMAC-SHA512; the generic adapter defaults to
    # SHA256 so local/manual providers can use the same endpoint. Accept both
    # hex and base64 encodings used by gateway SDKs.
    digestmod = hashlib.sha512 if str(provider).strip().lower() == "safepay" else hashlib.sha256
    digest = hmac.new(str(secret).encode(), canonical.encode(), digestmod)
    expected_hex = digest.hexdigest()
    expected_b64 = base64.b64encode(digest.digest()).decode()
    if not signature or not (
        hmac.compare_digest(str(signature), expected_hex)
        or hmac.compare_digest(str(signature), expected_b64)
    ):
        frappe.throw(_("Invalid billing webhook signature"), frappe.PermissionError)
    event_id = (event_id or "").strip()[:140]
    if not event_id or not provider or not company:
        frappe.throw(_("provider, event_id and company are required"))
    if not frappe.db.exists("Company", company):
        frappe.throw(_("Unknown business"), frappe.PermissionError)
    has_event_log = bool(frappe.db.exists("DocType", "FlexiPOS Billing Event"))
    old_event = frappe.db.get_value("Company", company, BILLING_EVENT_FIELD)
    if (has_event_log and frappe.db.exists("FlexiPOS Billing Event", event_id)) or old_event == event_id:
        return {"ok": True, "duplicate": True}
    status = (status or "").strip().title()
    if status not in SUBSCRIPTION_STATUSES:
        frappe.throw(_("Invalid subscription status"))
    values = {
        BILLING_PROVIDER_FIELD: str(provider).strip().lower()[:80],
        BILLING_EVENT_FIELD: event_id,
        SUBSCRIPTION_STATUS_FIELD: status,
    }
    period_end = payload.get("current_period_end")
    if period_end:
        values[CURRENT_PERIOD_END_FIELD] = get_datetime(period_end)
    if status == "Active" and (
        not period_end or get_datetime(period_end) <= now_datetime()
    ):
        frappe.throw(_("An active billing event needs a future period end"))
    token = payload.get("customer_token")
    if token:
        if len(str(token)) > 255:
            frappe.throw(_("Billing payload must contain tokenised payment data only"), frappe.PermissionError)
        values[BILLING_CUSTOMER_FIELD] = str(token)
    if has_event_log:
        frappe.get_doc(
            {
                "doctype": "FlexiPOS Billing Event",
                "event_id": event_id,
                "provider": str(provider).strip().lower()[:80],
                "company": company,
                "event_type": str(event_type or "unknown")[:140],
                "subscription_status": status,
                "payload_hash": hashlib.sha256(canonical.encode()).hexdigest(),
                "received_at": now_datetime(),
            }
        ).insert(ignore_permissions=True)
    frappe.db.set_value("Company", company, values, update_modified=False)
    return {"ok": True, "duplicate": False, "company": company, "status": status}


@frappe.whitelist()
def request_data_export():
    """Return a tenant-scoped privacy export without payment secrets."""
    company = _get_user_company()
    _require_admin(company)
    users = frappe.get_all(
        "User Permission", filters={"allow": "Company", "for_value": company}, pluck="user"
    )
    return {
        "company": frappe.db.get_value("Company", company, ["name", "company_name", "country", "default_currency", "flexipos_business_type", "flexipos_phone"], as_dict=True),
        "subscription": _subscription_payload(company),
        "users": frappe.get_all("User", filters={"name": ("in", users)}, fields=["name", "full_name", "email", "enabled", ROLE_FIELD]),
        "counts": {
            "items": frappe.db.count("Item", {COMPANY_FIELD: company}),
            "invoices": frappe.db.count("Sales Invoice", {"company": company}),
        },
        "generated_at": str(now_datetime()),
        "payment_data": "Payment card data is never stored by FlexiPOS.",
    }


@frappe.whitelist()
def request_data_deletion(confirm_company_name=None, confirmation=None):
    """Schedule tenant erasure after a 30-day recovery/legal-retention window."""
    company = _get_user_company()
    _require_admin(company)
    confirm_company_name = (confirm_company_name or confirmation or "").strip()
    if confirm_company_name not in (company, f"DELETE {company}"):
        frappe.throw(_("Type DELETE followed by the exact business name to confirm deletion"))
    retention_until = add_to_date(
        now_datetime(), days=_default_deletion_retention_days()
    )
    frappe.db.set_value(
        "Company", company,
        {
            SUBSCRIPTION_STATUS_FIELD: "Cancelled",
            DELETION_REQUESTED_FIELD: now_datetime(),
            RETENTION_UNTIL_FIELD: retention_until.date(),
        },
        update_modified=False,
    )
    return {"company": company, "status": "scheduled", "retention_until": str(retention_until.date())}


@frappe.whitelist()
def request_account_deletion(confirm_company_name=None, confirmation=None):
    """Compatibility name for the account/privacy settings UI."""
    return request_data_deletion(confirm_company_name, confirmation)


@frappe.whitelist()
def cancel_data_deletion():
    company = _get_user_company()
    _require_admin(company)
    values = frappe.db.get_value(
        "Company",
        company,
        [SUBSCRIPTION_STATUS_FIELD, TRIAL_ENDS_FIELD, CURRENT_PERIOD_END_FIELD],
        as_dict=True,
    ) or {}
    if values.get(SUBSCRIPTION_STATUS_FIELD) == "Archived":
        frappe.throw(_("Archived business data cannot be restored"), frappe.PermissionError)
    now = now_datetime()
    if values.get(CURRENT_PERIOD_END_FIELD) and get_datetime(values[CURRENT_PERIOD_END_FIELD]) > now:
        restored_status = "Active"
    elif values.get(TRIAL_ENDS_FIELD) and get_datetime(values[TRIAL_ENDS_FIELD]) > now:
        restored_status = "Trialing"
    else:
        restored_status = "Past Due"
    frappe.db.set_value(
        "Company",
        company,
        {
            DELETION_REQUESTED_FIELD: None,
            RETENTION_UNTIL_FIELD: None,
            SUBSCRIPTION_STATUS_FIELD: restored_status,
        },
        update_modified=False,
    )
    return {"company": company, "subscription": _subscription_payload(company)}


def _get_business_config(company):
    values = frappe.db.get_value(
        "Company",
        company,
        [CATEGORY_NAMES_FIELD, DEFAULT_TAX_RATE_FIELD, SERVICE_STYLES_FIELD],
        as_dict=True,
    ) or {}
    try:
        categories = json.loads(values.get(CATEGORY_NAMES_FIELD) or "[]")
    except (TypeError, json.JSONDecodeError):
        categories = []
    if not isinstance(categories, list):
        categories = []
    styles = [
        value.strip()
        for value in (values.get(SERVICE_STYLES_FIELD) or "").split(",")
        if value.strip() in ("Dine-in", "Takeaway", "Delivery")
    ]
    return {
        "categories": [str(value) for value in categories if value],
        "default_tax_rate": flt(values.get(DEFAULT_TAX_RATE_FIELD)),
        "service_styles": styles,
    }


@frappe.whitelist()
def save_business_setup(categories_json="[]", service_styles_json="[]", default_tax_rate=0, table_count=0):
    """Persist onboarding fields that must be identical on every register."""
    _require_screen_access("inventory")
    _require_admin()
    company = _get_user_company()
    categories = _json_list(categories_json, _("categories"))
    styles = _json_list(service_styles_json, _("service styles"))

    clean_categories = []
    for value in categories[:100]:
        name = str(value).strip()[:140]
        if name and name not in clean_categories:
            clean_categories.append(name)
            _ensure_item_group(name)

    clean_styles = []
    for value in styles:
        if value in ("Dine-in", "Takeaway", "Delivery") and value not in clean_styles:
            clean_styles.append(value)

    tax_rate = flt(default_tax_rate)
    if tax_rate < 0 or tax_rate > 100:
        frappe.throw(_("Default tax rate must be between 0 and 100"))
    frappe.db.set_value(
        "Company",
        company,
        {
            CATEGORY_NAMES_FIELD: json.dumps(clean_categories),
            SERVICE_STYLES_FIELD: ",".join(clean_styles),
            DEFAULT_TAX_RATE_FIELD: tax_rate,
        },
    )

    count = max(0, min(cint(table_count), 500))
    for number in range(1, count + 1):
        _upsert_shared_table(company, str(number), "Free", None, None)
    return _get_business_config(company)


def _json_list(value, label):
    if isinstance(value, list):
        return value
    try:
        result = json.loads(value or "[]")
    except (TypeError, json.JSONDecodeError):
        frappe.throw(_("Invalid {0}").format(label))
    if not isinstance(result, list):
        frappe.throw(_("{0} must be a list").format(label))
    return result


def _setup_business(company_name, business_type, phone):
    """Shared setup core; caller owns commit/rollback."""
    company = _create_company(company_name, business_type, phone)
    branch = _create_branch(company)
    customer = _ensure_walk_in_customer()
    pos_profile = _create_pos_profile(company, customer)
    _link_current_user(company)
    subscription = _subscription_payload(company.name)
    return {
        "company": company.name,
        "company_abbr": company.abbr,
        "business_type": company.flexipos_business_type,
        "branch": branch.name,
        "pos_profile": pos_profile.name,
        "customer": customer,
        "currency": company.default_currency,
        "warehouse": pos_profile.warehouse,
        "price_list": pos_profile.selling_price_list,
        "subscription": subscription,
        **_subscription_client_payload(company.name),
    }


@frappe.whitelist(methods=["GET", "POST"])
def get_device_token():
    """Issue API key/secret for header token auth. GET-friendly so a
    fresh cookie session (password login) can call it without needing a
    CSRF token — the app then uses `Authorization: token key:secret`
    for everything, which works in browsers and skips CSRF checks."""
    if frappe.session.user == "Guest":
        frappe.throw(_("Login required"), frappe.AuthenticationError)
    return _get_api_credentials(frappe.session.user)


def _get_api_credentials(user):
    """Return the user's API key/secret, generating them on first use."""
    from frappe.utils.password import get_decrypted_password

    user_doc = frappe.get_doc("User", user)
    api_secret = None
    if user_doc.api_key:
        api_secret = get_decrypted_password(
            "User", user, "api_secret", raise_exception=False
        )
    if not api_secret:
        api_secret = frappe.generate_hash(length=15)
        if not user_doc.api_key:
            user_doc.api_key = frappe.generate_hash(length=15)
        user_doc.api_secret = api_secret
        user_doc.flags.ignore_permissions = True
        user_doc.save(ignore_permissions=True)
    return {"api_key": user_doc.api_key, "api_secret": api_secret}


def _rate_limit_signup():
    ip = frappe.local.request_ip or "unknown"
    cache_key = f"flexipos_signup:{ip}"
    count = cint(frappe.cache().get_value(cache_key))
    if count >= 5:
        frappe.throw(_("Too many signups from this network. Try again later."))
    frappe.cache().set_value(cache_key, count + 1, expires_in_sec=3600)


def _make_abbr(company_name):
    abbr = "".join(word[0] for word in company_name.split()).upper()[:5] or "CO"
    candidate, counter = abbr, 1
    while frappe.db.exists("Company", {"abbr": candidate}):
        counter += 1
        candidate = f"{abbr}{counter}"
    return candidate


def _create_company(company_name, business_type, phone):
    company = frappe.get_doc(
        {
            "doctype": "Company",
            "company_name": company_name,
            "abbr": _make_abbr(company_name),
            "default_currency": DEFAULT_CURRENCY,
            "country": DEFAULT_COUNTRY,
            "create_chart_of_accounts_based_on": "Standard Template",
            "chart_of_accounts": "Standard",
            "flexipos_business_type": business_type,
            "flexipos_phone": phone,
            CATEGORY_NAMES_FIELD: "[]",
            DEFAULT_TAX_RATE_FIELD: 0,
            SERVICE_STYLES_FIELD: "Dine-in,Takeaway" if business_type == "Restaurant" else "",
            SUBSCRIPTION_STATUS_FIELD: "Trialing",
            TRIAL_ENDS_FIELD: add_to_date(now_datetime(), days=_default_trial_days()),
            BILLING_EMAIL_FIELD: frappe.session.user if "@" in (frappe.session.user or "") else "",
            "enable_perpetual_inventory": 0,
        }
    )
    company.insert(ignore_permissions=True)
    return company


def _create_branch(company):
    branch_name = f"{company.name} - Main"
    if frappe.db.exists("Branch", branch_name):
        branch = frappe.get_doc("Branch", branch_name)
        owner = branch.get(BRANCH_COMPANY_FIELD)
        if owner and owner != company.name:
            frappe.throw(
                _("The default branch belongs to another business"),
                frappe.PermissionError,
            )
        if not owner:
            branch.set(BRANCH_COMPANY_FIELD, company.name)
            branch.flags.ignore_permissions = True
            branch.save()
        return branch
    branch = frappe.get_doc(
        {
            "doctype": "Branch",
            "branch": branch_name,
            BRANCH_COMPANY_FIELD: company.name,
        }
    )
    branch.insert(ignore_permissions=True)
    return branch


def _ensure_walk_in_customer():
    if frappe.db.exists("Customer", WALK_IN_CUSTOMER):
        return WALK_IN_CUSTOMER
    # Customer requires LEAF (non-group) nodes; the Selling Settings
    # defaults are often group nodes like "All Customer Groups".
    customer_group = frappe.db.get_value(
        "Customer Group", {"customer_group_name": "Individual"}
    ) or frappe.db.get_value("Customer Group", {"is_group": 0})
    territory = frappe.db.get_value(
        "Territory", {"territory_name": "Rest Of The World"}
    ) or frappe.db.get_value("Territory", {"is_group": 0})

    customer = frappe.get_doc(
        {
            "doctype": "Customer",
            "customer_name": WALK_IN_CUSTOMER,
            "customer_type": "Individual",
            "customer_group": customer_group,
            "territory": territory,
        }
    )
    customer.insert(ignore_permissions=True)
    return customer.name


def _create_pos_profile(company, customer):
    warehouse = f"Stores - {company.abbr}"
    pos_profile = frappe.get_doc(
        {
            "doctype": "POS Profile",
            "name": f"{company.name} POS",
            "company": company.name,
            "customer": customer,
            "warehouse": warehouse,
            "currency": company.default_currency,
            "selling_price_list": DEFAULT_PRICE_LIST,
            "write_off_account": f"Write Off - {company.abbr}",
            "write_off_cost_center": f"Main - {company.abbr}",
            "update_stock": 1,
            "payments": [{"mode_of_payment": "Cash", "default": 1}],
            "applicable_for_users": [{"user": frappe.session.user, "default": 1}],
        }
    )
    pos_profile.insert(ignore_permissions=True)
    return pos_profile


def _link_current_user(company):
    user = frappe.session.user
    if user == "Administrator":
        return

    user_doc = frappe.get_doc("User", user)
    existing_roles = {r.role for r in user_doc.roles}
    for role in ("Sales User", "Accounts User", "Stock User"):
        if role not in existing_roles and frappe.db.exists("Role", role):
            user_doc.append("roles", {"role": role})
    # The user completing onboarding owns the business, so they are its
    # Admin — set explicitly rather than leaving flexipos_role empty,
    # so Team & Roles has one unambiguous source of truth for who can
    # manage staff.
    user_doc.set(ROLE_FIELD, ADMIN_ROLE)
    user_doc.flags.ignore_permissions = True
    user_doc.save()

    if not frappe.db.exists(
        "User Permission",
        {"user": user, "allow": "Company", "for_value": company.name},
    ):
        frappe.get_doc(
            {
                "doctype": "User Permission",
                "user": user,
                "allow": "Company",
                "for_value": company.name,
            }
        ).insert(ignore_permissions=True)


# ---------------------------------------------------------------------------
# 2. sync_inventory
# ---------------------------------------------------------------------------

@frappe.whitelist()
def sync_inventory(last_sync_datetime=None):
    """Delta-sync of the caller's Items, selling prices and categories.

    Tenant isolation: every query filters on flexipos_company, so a
    business only ever receives its own catalog.

    Item and Item Price deltas are fetched independently because a price
    change does not touch Item.modified. The client merges prices into
    its local item rows by item_code.
    """
    _require_any_screen_access("quick_sale", "inventory")
    _ensure_custom_fields()
    company = _get_user_company()
    profile = _get_pos_profile_for_company(None, company, frappe.session.user)
    selling_price_list = profile.selling_price_list
    server_time = str(now_datetime())

    item_filters = {"is_sales_item": 1, COMPANY_FIELD: company}
    if last_sync_datetime:
        item_filters["modified"] = (">", get_datetime(last_sync_datetime))

    items = frappe.get_all(
        "Item",
        filters=item_filters,
        fields=[
            "item_code",
            "item_name",
            "item_group",
            "stock_uom",
            "image",
            "disabled",
            "modified",
            "description",
            "valuation_rate",
            RX_FIELD,
            COLD_CHAIN_FIELD,
            DURATION_FIELD,
            MATERIAL_FIELD,
            SEASON_FIELD,
            GENDER_FIELD,
            VARIANT_MATRIX_FIELD,
            TAX_RATE_FIELD,
            STOCK_QTY_FIELD,
            DIETARY_FIELD,
            RECIPE_DEPLETION_FIELD,
            GENERIC_NAME_FIELD, BRAND_NAME_FIELD, BATCH_NO_FIELD,
            EXPIRY_DATE_FIELD, DOSAGE_FORM_FIELD, RACK_BIN_FIELD,
            REORDER_POINT_FIELD,
            DEPARTMENT_FIELD, SHELF_LOCATION_FIELD, SUPPLIER_FIELD,
            PACK_SIZE_FIELD, REORDER_QTY_FIELD, LOW_STOCK_ALERT_FIELD,
            SHELF_LIFE_FIELD, LEAD_TIME_FIELD, ALLERGENS_FIELD,
            DEFAULT_SIZE_FIELD, ALLOW_CUSTOM_MESSAGE_FIELD, MADE_TO_ORDER_FIELD,
        ],
        limit_page_length=0,
    )
    if items:
        item_codes = [i.item_code for i in items]
        links = frappe.get_all(
            "FlexiPOS Item Modifier Group",
            filters={"parent": ("in", item_codes), "parenttype": "Item"},
            fields=["parent", "modifier_group"],
            order_by="idx",
        )
        groups_by_item = {}
        for link in links:
            groups_by_item.setdefault(link.parent, []).append(link.modifier_group)
        for item in items:
            item["modifier_groups"] = groups_by_item.get(item.item_code, [])

        # One primary barcode per item (the first row in its Item Barcode
        # child table) — enough for scan-to-add lookups without exposing
        # ERPNext's multi-barcode-per-UOM feature to the client.
        barcode_rows = frappe.get_all(
            "Item Barcode",
            filters={"parent": ("in", item_codes), "parenttype": "Item"},
            fields=["parent", "barcode"],
            order_by="parent, idx",
        )
        barcode_by_item = {}
        for row in barcode_rows:
            barcode_by_item.setdefault(row.parent, row.barcode)
        for item in items:
            item["barcode"] = barcode_by_item.get(item.item_code)

    # Every modifier group belonging to the business, with its options —
    # items reference groups by name, so the client resolves the join
    # locally instead of re-sending the group payload per item.
    modifier_groups = []
    group_names = frappe.get_all(
        "FlexiPOS Modifier Group",
        filters={"flexipos_company": company},
        pluck="name",
    )
    for name in group_names:
        group = frappe.get_cached_doc("FlexiPOS Modifier Group", name)
        modifier_groups.append(
            {
                "name": group.name,
                "group_name": group.group_name,
                "selection_type": group.selection_type,
                "required": group.required,
                "min_select": group.min_select,
                "max_select": group.max_select,
                "options": [
                    {
                        "modifier": o.modifier,
                        "label": o.label,
                        "price": flt(o.price),
                        "is_default": o.is_default,
                    }
                    for o in group.options
                ],
            }
        )

    prices = []
    company_item_codes = frappe.get_all(
        "Item", filters={COMPANY_FIELD: company}, pluck="name", limit_page_length=0
    )
    if company_item_codes:
        price_filters = {
            "selling": 1,
            "price_list": selling_price_list,
            "item_code": ("in", company_item_codes),
        }
        if last_sync_datetime:
            price_filters["modified"] = (">", get_datetime(last_sync_datetime))
        prices = frappe.get_all(
            "Item Price",
            filters=price_filters,
            fields=["item_code", "price_list_rate", "currency", "modified"],
            limit_page_length=0,
        )

    groups = frappe.get_all(
        "Item",
        filters={COMPANY_FIELD: company, "disabled": 0},
        fields=["item_group"],
        limit_page_length=0,
    )
    business_config = _get_business_config(company)
    category_names = sorted(
        {g.item_group for g in groups if g.item_group}
        | set(business_config["categories"])
    )
    company_category_images = _get_company_category_images(company)
    legacy_category_images = {}
    if category_names:
        legacy_rows = frappe.get_all(
            "Item Group",
            filters={"name": ("in", category_names)},
            fields=["name", CATEGORY_IMAGE_FIELD],
        )
        legacy_category_images = {
            row.name: row.get(CATEGORY_IMAGE_FIELD) for row in legacy_rows
        }
    categories = [
        {
            "name": name,
            "image": company_category_images.get(name)
            or legacy_category_images.get(name),
        }
        for name in category_names
    ]

    return {
        "server_time": server_time,
        "items": items,
        "prices": prices,
        "categories": categories,
        "modifier_groups": modifier_groups,
        "business": business_config,
    }


# ---------------------------------------------------------------------------
# 2b. Inventory management
# ---------------------------------------------------------------------------

@frappe.whitelist()
def save_item(item_json):
    """Create or update a product for the caller's business.

    Payload:
        {
          "item_code": "ZTG-CHAI",   # present → update, absent → create
          "item_name": "Chai",
          "price": 60,
          "category": "Drinks",       # Item Group, created if missing
          "uom": "Nos",
          "track_stock": 0,           # default off: micro-retailers first
          "disabled": 0,
          "barcode": "6291041234567",  # omit to leave unchanged, "" to clear
          "requires_prescription": 0,  # Pharmacy: Rx badge
          "cold_chain": 0,             # Pharmacy: cold-chain badge
          "duration_minutes": 30,      # Service duration / Restaurant prep
          "sku": "CL-2210",            # create only: item_code becomes
                                       # "<company abbr>-CL-2210"
          "cost_price": 60,            # Item.valuation_rate
          "tax_rate": 5,               # inclusive item tax percentage
          "stock_qty": 40,             # simple on-hand count, not ledger
          "dietary_flags": ["Halal"],  # Restaurant (list or CSV string)
          "recipe_depletion": 1,       # Restaurant: recipe/BOM flag
          "material": "100% Linen",    # Clothing
          "season": "SS26",            # Clothing
          "gender": "Unisex",          # Clothing: Men/Women/Unisex/Kids
          "variant_matrix": {...},     # Clothing size x colour stock matrix
                                       # (see VARIANT_MATRIX_FIELD comment);
                                       # omit to leave unchanged, null/{} to
                                       # clear
          "modifier_groups": ["Size", "Add-ons"]   # names of groups this
                                                     # item offers; omit to
                                                     # leave unchanged
        }

    Returns the same row shape sync_inventory uses (plus price) so the
    client can upsert its local cache immediately.
    """
    _require_screen_access("inventory")
    data = item_json
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            frappe.throw(_("item_json is not valid JSON"))
    if not isinstance(data, dict):
        frappe.throw(_("Expected an item object"))

    _ensure_custom_fields()
    company = _get_user_company()

    item_name = (data.get("item_name") or "").strip()
    if not item_name:
        frappe.throw(_("Product name is required"))
    description = (data.get("description") or "").strip()
    price = flt(data.get("price"))
    if price < 0:
        frappe.throw(_("Price cannot be negative"))
    tax_rate = flt(data.get("tax_rate"))
    if tax_rate < 0 or tax_rate > 100:
        frappe.throw(_("Tax rate must be between 0 and 100"))
    category = (data.get("category") or "").strip() or "Products"
    uom = (data.get("uom") or "Nos").strip()
    if not frappe.db.exists("UOM", uom):
        uom = "Nos"

    item_group = _ensure_item_group(category)
    item_code = (data.get("item_code") or "").strip()
    barcode = (data.get("barcode") or "").strip() or None

    if item_code:
        _require_document_company(
            "Item",
            item_code,
            company,
            company_field=COMPANY_FIELD,
            label=_("Product"),
        )
        item = frappe.get_doc("Item", item_code)
        item.item_name = item_name
        item.item_group = item_group
        item.description = description
        item.disabled = cint(data.get("disabled"))
        if "requires_prescription" in data:
            item.set(RX_FIELD, cint(data.get("requires_prescription")))
        if "cold_chain" in data:
            item.set(COLD_CHAIN_FIELD, cint(data.get("cold_chain")))
        if "duration_minutes" in data:
            item.set(DURATION_FIELD, cint(data.get("duration_minutes")) or None)
        if "cost_price" in data:
            item.valuation_rate = flt(data.get("cost_price"))
        if "material" in data:
            item.set(MATERIAL_FIELD, (data.get("material") or "").strip())
        if "season" in data:
            item.set(SEASON_FIELD, (data.get("season") or "").strip())
        if "gender" in data:
            item.set(GENDER_FIELD, _clean_gender(data.get("gender")))
        if "variant_matrix" in data:
            item.set(VARIANT_MATRIX_FIELD, _clean_variant_matrix(data.get("variant_matrix")))
        if "tax_rate" in data:
            item.set(TAX_RATE_FIELD, tax_rate)
        if "stock_qty" in data:
            item.set(STOCK_QTY_FIELD, max(cint(data.get("stock_qty")), 0))
        if "dietary_flags" in data:
            item.set(DIETARY_FIELD, _clean_dietary_flags(data.get("dietary_flags")))
        if "recipe_depletion" in data:
            item.set(RECIPE_DEPLETION_FIELD, cint(data.get("recipe_depletion")))
        for key, field in (("generic_name", GENERIC_NAME_FIELD), ("brand_name", BRAND_NAME_FIELD), ("batch_no", BATCH_NO_FIELD), ("expiry_date", EXPIRY_DATE_FIELD), ("dosage_form", DOSAGE_FORM_FIELD), ("rack_bin", RACK_BIN_FIELD)):
            if key in data:
                item.set(field, (data.get(key) or "").strip())
        if "reorder_point" in data:
            item.set(REORDER_POINT_FIELD, max(cint(data.get("reorder_point")), 0))
        for key, field in (("department", DEPARTMENT_FIELD), ("shelf_location", SHELF_LOCATION_FIELD), ("supplier", SUPPLIER_FIELD), ("pack_size", PACK_SIZE_FIELD)):
            if key in data:
                item.set(field, (data.get(key) or "").strip())
        if "reorder_qty" in data:
            item.set(REORDER_QTY_FIELD, max(cint(data.get("reorder_qty")), 0))
        if "low_stock_alert" in data:
            item.set(LOW_STOCK_ALERT_FIELD, cint(data.get("low_stock_alert")))
        for key, field in (("shelf_life", SHELF_LIFE_FIELD), ("lead_time", LEAD_TIME_FIELD), ("allergens", ALLERGENS_FIELD), ("default_size", DEFAULT_SIZE_FIELD)):
            if key in data:
                item.set(field, (data.get(key) or "").strip())
        if "allow_custom_message" in data:
            item.set(ALLOW_CUSTOM_MESSAGE_FIELD, cint(data.get("allow_custom_message")))
        if "made_to_order" in data:
            item.set(MADE_TO_ORDER_FIELD, cint(data.get("made_to_order")))
        item.flags.ignore_permissions = True
        item.save()
    else:
        sku = (data.get("sku") or "").strip()
        item = frappe.get_doc(
            {
                "doctype": "Item",
                "item_code": _make_item_code(company, sku or item_name),
                "item_name": item_name,
                "item_group": item_group,
                "description": description,
                "stock_uom": uom,
                "is_stock_item": cint(data.get("track_stock")),
                "is_sales_item": 1,
                "valuation_rate": flt(data.get("cost_price")),
                COMPANY_FIELD: company,
                RX_FIELD: cint(data.get("requires_prescription")),
                COLD_CHAIN_FIELD: cint(data.get("cold_chain")),
                DURATION_FIELD: cint(data.get("duration_minutes")) or None,
                MATERIAL_FIELD: (data.get("material") or "").strip(),
                SEASON_FIELD: (data.get("season") or "").strip(),
                GENDER_FIELD: _clean_gender(data.get("gender")),
                VARIANT_MATRIX_FIELD: _clean_variant_matrix(data.get("variant_matrix")),
                TAX_RATE_FIELD: tax_rate,
                STOCK_QTY_FIELD: max(cint(data.get("stock_qty")), 0),
                DIETARY_FIELD: _clean_dietary_flags(data.get("dietary_flags")),
                RECIPE_DEPLETION_FIELD: cint(data.get("recipe_depletion")),
                GENERIC_NAME_FIELD: (data.get("generic_name") or "").strip(),
                BRAND_NAME_FIELD: (data.get("brand_name") or "").strip(),
                BATCH_NO_FIELD: (data.get("batch_no") or "").strip(),
                EXPIRY_DATE_FIELD: (data.get("expiry_date") or "").strip(),
                DOSAGE_FORM_FIELD: (data.get("dosage_form") or "").strip(),
                RACK_BIN_FIELD: (data.get("rack_bin") or "").strip(),
                REORDER_POINT_FIELD: max(cint(data.get("reorder_point")), 0),
                DEPARTMENT_FIELD: (data.get("department") or "").strip(),
                SHELF_LOCATION_FIELD: (data.get("shelf_location") or "").strip(),
                SUPPLIER_FIELD: (data.get("supplier") or "").strip(),
                PACK_SIZE_FIELD: (data.get("pack_size") or "").strip(),
                REORDER_QTY_FIELD: max(cint(data.get("reorder_qty")), 0),
                LOW_STOCK_ALERT_FIELD: cint(data.get("low_stock_alert")),
                SHELF_LIFE_FIELD: (data.get("shelf_life") or "").strip(),
                LEAD_TIME_FIELD: (data.get("lead_time") or "").strip(),
                ALLERGENS_FIELD: (data.get("allergens") or "").strip(),
                DEFAULT_SIZE_FIELD: (data.get("default_size") or "").strip(),
                ALLOW_CUSTOM_MESSAGE_FIELD: cint(data.get("allow_custom_message")),
                MADE_TO_ORDER_FIELD: cint(data.get("made_to_order")),
            }
        )
        item.insert(ignore_permissions=True)

    profile = _get_pos_profile_for_company(None, company, frappe.session.user)
    _set_selling_price(item.name, price, profile.selling_price_list)

    # "barcode" present (even blank) → replace the item's primary barcode;
    # absent (key missing) → leave whatever is already assigned alone.
    if "barcode" in data:
        _set_primary_barcode(item, barcode)

    # "modifier_groups" present (even empty) → replace the item's group
    # list; absent → leave whatever is already assigned alone.
    if data.get("modifier_groups") is not None:
        _assign_modifier_groups(item, company, data["modifier_groups"])

    item.reload()
    return {
        "item_code": item.name,
        "item_name": item.item_name,
        "item_group": item.item_group,
        "description": item.description,
        "stock_uom": item.stock_uom,
        "image": item.image,
        "disabled": item.disabled,
        "modified": str(item.modified),
        "price": price,
        "barcode": item.get("barcodes")[0].barcode if item.get("barcodes") else None,
        "requires_prescription": item.get(RX_FIELD),
        "cold_chain": item.get(COLD_CHAIN_FIELD),
        "duration_minutes": item.get(DURATION_FIELD),
        "cost_price": flt(item.valuation_rate),
        "material": item.get(MATERIAL_FIELD),
        "season": item.get(SEASON_FIELD),
        "gender": item.get(GENDER_FIELD),
        "variant_matrix": item.get(VARIANT_MATRIX_FIELD),
        "tax_rate": flt(item.get(TAX_RATE_FIELD)),
        "stock_qty": item.get(STOCK_QTY_FIELD),
        "dietary_flags": item.get(DIETARY_FIELD),
        "recipe_depletion": item.get(RECIPE_DEPLETION_FIELD),
        "generic_name": item.get(GENERIC_NAME_FIELD),
        "brand_name": item.get(BRAND_NAME_FIELD),
        "batch_no": item.get(BATCH_NO_FIELD),
        "expiry_date": item.get(EXPIRY_DATE_FIELD),
        "dosage_form": item.get(DOSAGE_FORM_FIELD),
        "rack_bin": item.get(RACK_BIN_FIELD),
        "reorder_point": item.get(REORDER_POINT_FIELD),
        "department": item.get(DEPARTMENT_FIELD),
        "shelf_location": item.get(SHELF_LOCATION_FIELD),
        "supplier": item.get(SUPPLIER_FIELD),
        "pack_size": item.get(PACK_SIZE_FIELD),
        "reorder_qty": item.get(REORDER_QTY_FIELD),
        "low_stock_alert": item.get(LOW_STOCK_ALERT_FIELD),
        "shelf_life": item.get(SHELF_LIFE_FIELD),
        "lead_time": item.get(LEAD_TIME_FIELD),
        "allergens": item.get(ALLERGENS_FIELD),
        "default_size": item.get(DEFAULT_SIZE_FIELD),
        "allow_custom_message": item.get(ALLOW_CUSTOM_MESSAGE_FIELD),
        "made_to_order": item.get(MADE_TO_ORDER_FIELD),
        "modifier_groups": [g.modifier_group for g in item.get(MODIFIER_GROUPS_FIELD)],
    }


def _clean_gender(value):
    value = (value or "").strip().title()
    return value if value in GENDER_OPTIONS else ""


def _clean_dietary_flags(raw):
    """Accept a list or CSV string; keep only known options, in the
    canonical order, as a CSV string."""
    if not raw:
        return ""
    parts = raw if isinstance(raw, list) else str(raw).split(",")
    chosen = {str(p).strip().lower() for p in parts}
    return ",".join(o for o in DIETARY_OPTIONS if o.lower() in chosen)


def _clean_variant_matrix(raw):
    """Validate and normalise the clothing size x colour matrix into the
    canonical JSON shape (see VARIANT_MATRIX_FIELD) so the client can
    trust whatever it syncs back. Returns None to clear the field."""
    if not raw:
        return None
    data = raw
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            frappe.throw(_("variant_matrix is not valid JSON"))
    if not isinstance(data, dict):
        frappe.throw(_("variant_matrix must be an object"))

    colours = []
    seen = set()
    for colour in data.get("colours") or []:
        if not isinstance(colour, dict):
            continue
        name = (colour.get("name") or "").strip()[:40]
        if not name or name.lower() in seen:
            continue
        seen.add(name.lower())
        colours.append({"name": name, "hex": (colour.get("hex") or "").strip()[:9]})

    sizes = []
    for size in data.get("sizes") or []:
        size = str(size).strip()[:20]
        if size and size not in sizes:
            sizes.append(size)

    if not colours or not sizes:
        return None

    qty_in = data.get("qty") or {}
    qty = {}
    for colour in colours:
        row = qty_in.get(colour["name"])
        row = row if isinstance(row, dict) else {}
        qty[colour["name"]] = {size: max(cint(row.get(size)), 0) for size in sizes}

    return json.dumps({"colours": colours, "sizes": sizes, "qty": qty})


def _set_primary_barcode(item, barcode):
    """Replace the item's Item Barcode child table with a single row (or
    clear it if `barcode` is falsy). FlexiPOS only ever shows/edits one
    barcode per item, so this never has to merge with existing rows."""
    item.set("barcodes", [{"barcode": barcode}] if barcode else [])
    item.flags.ignore_permissions = True
    item.save()


@frappe.whitelist()
def lookup_item_by_barcode(barcode):
    """Scan-to-add: resolve a scanned/typed barcode to an item_code within
    the caller's business. Returns None if no item has that barcode."""
    _require_any_screen_access("quick_sale", "inventory")
    company = _get_user_company()
    barcode = (barcode or "").strip()
    if not barcode:
        return None

    item_code = frappe.db.get_value(
        "Item Barcode", {"barcode": barcode, "parenttype": "Item"}, "parent"
    )
    if not item_code:
        return None
    owner = frappe.db.get_value("Item", item_code, COMPANY_FIELD)
    if owner != company:
        return None
    return {"item_code": item_code}


def _assign_modifier_groups(item, company, group_names):
    """Replace the item's modifier-group assignments. `group_names` is
    the full desired list of FlexiPOS Modifier Group names (must already
    belong to this business — assign_modifier_groups doesn't create
    groups, use save_modifier_group for that)."""
    if not isinstance(group_names, list):
        frappe.throw(_("modifier_groups must be a list"))

    for name in group_names:
        _require_document_company(
            "FlexiPOS Modifier Group",
            name,
            company,
            company_field="flexipos_company",
            label=_("Modifier group"),
        )

    item.set(MODIFIER_GROUPS_FIELD, [{"modifier_group": name} for name in group_names])
    item.flags.ignore_permissions = True
    item.save()


def _get_or_create_modifier(company, modifier_name, default_price=0):
    """Reuse the business's FlexiPOS Modifier of that name, creating it
    on first use — the master's price only seeds new options (each
    option row can override it)."""
    existing = frappe.db.get_value(
        "FlexiPOS Modifier",
        {"modifier_name": modifier_name, "flexipos_company": company},
    )
    if existing:
        return existing
    modifier = frappe.new_doc("FlexiPOS Modifier")
    modifier.modifier_name = modifier_name
    modifier.flexipos_company = company
    modifier.price = default_price
    modifier.flags.ignore_permissions = True
    modifier.insert()
    return modifier.name


@frappe.whitelist()
def save_modifier_group(group_json):
    """Create or update a reusable modifier group for the caller's
    business (e.g. "Size" with Small/Medium/Large, or "Add-ons" with
    Extra Cheese/No Onions).

    Each option row points at a FlexiPOS Modifier master. Pass
    "modifier" to link an existing one, or just "label" — the
    business's modifier of that name is reused, or created on first
    use. Either way the same modifier can sit in any number of groups.

    Payload:
        {
          "name": "Size",             # present → update, absent → create
          "group_name": "Size",
          "selection_type": "Single", # "Single" | "Multiple"
          "required": 1,
          "min_select": 0,
          "max_select": 0,
          "options": [
            {"label": "Small", "price": 0, "is_default": 1},
            {"modifier": "MOD-00007", "price": 50}
          ]
        }
    """
    _require_screen_access("inventory")
    data = group_json
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            frappe.throw(_("group_json is not valid JSON"))
    if not isinstance(data, dict):
        frappe.throw(_("Expected a modifier group object"))

    company = _get_user_company()

    group_name = (data.get("group_name") or "").strip()
    if not group_name:
        frappe.throw(_("Group name is required"))
    selection_type = data.get("selection_type") or "Single"
    if selection_type not in ("Single", "Multiple"):
        frappe.throw(_("selection_type must be Single or Multiple"))
    options = data.get("options") or []
    if not isinstance(options, list) or not options:
        frappe.throw(_("At least one option is required"))

    option_rows = []
    for opt in options:
        if not isinstance(opt, dict):
            continue
        modifier_id = (opt.get("modifier") or "").strip()
        label = (opt.get("label") or "").strip()
        if modifier_id:
            _require_document_company(
                "FlexiPOS Modifier",
                modifier_id,
                company,
                company_field="flexipos_company",
                label=_("Modifier"),
            )
            modifier = frappe.db.get_value(
                "FlexiPOS Modifier",
                modifier_id,
                ["flexipos_company", "modifier_name"],
                as_dict=True,
            )
            label = modifier.modifier_name
        elif label:
            modifier_id = _get_or_create_modifier(company, label, flt(opt.get("price")))
        else:
            continue
        option_rows.append(
            {
                "modifier": modifier_id,
                "label": label,
                "price": flt(opt.get("price")),
                "is_default": cint(opt.get("is_default")),
            }
        )
    if not option_rows:
        frappe.throw(_("At least one option is required"))

    existing_name = (data.get("name") or "").strip()
    if existing_name:
        _require_document_company(
            "FlexiPOS Modifier Group",
            existing_name,
            company,
            company_field="flexipos_company",
            label=_("Modifier group"),
        )
        group = frappe.get_doc("FlexiPOS Modifier Group", existing_name)
        group.group_name = group_name
    else:
        group = frappe.new_doc("FlexiPOS Modifier Group")
        group.group_name = group_name
        group.flexipos_company = company

    group.selection_type = selection_type
    group.required = cint(data.get("required"))
    group.min_select = cint(data.get("min_select"))
    group.max_select = cint(data.get("max_select"))
    group.set("options", option_rows)
    group.flags.ignore_permissions = True
    group.save()

    return {
        "name": group.name,
        "group_name": group.group_name,
        "selection_type": group.selection_type,
        "required": group.required,
        "min_select": group.min_select,
        "max_select": group.max_select,
        "options": [
            {
                "modifier": o.modifier,
                "label": o.label,
                "price": flt(o.price),
                "is_default": o.is_default,
            }
            for o in group.options
        ],
    }


@frappe.whitelist()
def delete_modifier_group(name):
    """Remove a modifier group. Fails loudly if any item still
    references it — the caller should unassign it from those items
    first (past invoices are unaffected either way, since a chosen
    modifier is baked into the invoice line's rate/description, not a
    live reference)."""
    _require_screen_access("inventory")
    company = _get_user_company()
    _require_document_company(
        "FlexiPOS Modifier Group",
        name,
        company,
        company_field="flexipos_company",
        label=_("Modifier group"),
    )

    in_use = frappe.get_all(
        "FlexiPOS Item Modifier Group",
        filters={"modifier_group": name, "parenttype": "Item"},
        limit=1,
    )
    if in_use:
        frappe.throw(_("Remove this group from its items before deleting it"))

    frappe.delete_doc("FlexiPOS Modifier Group", name, ignore_permissions=True)
    return {"deleted": name}


@frappe.whitelist()
def upload_image(target_type, target_name, filename, content_base64):
    """Attach a public photo to a product (Item.image) or a category
    (Item Group.flexipos_image). Base64 payload keeps the client simple
    and identical across mobile/desktop/web."""
    _require_screen_access("inventory")
    _ensure_custom_fields()
    company = _get_user_company()

    filename = (filename or "photo.jpg").replace("\\", "/").split("/")[-1]
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ALLOWED_IMAGE_EXTENSIONS:
        frappe.throw(_("Only JPG, PNG or WEBP images are allowed"))
    try:
        raw = base64.b64decode(content_base64 or "", validate=True)
    except Exception:
        frappe.throw(_("Invalid image data"))
    if not raw:
        frappe.throw(_("Image is empty"))
    if len(raw) > MAX_IMAGE_BYTES:
        frappe.throw(_("Image is too large (max 3 MB)"))

    category_images = None
    if target_type == "item":
        _require_document_company(
            "Item",
            target_name,
            company,
            company_field=COMPANY_FIELD,
            label=_("Product"),
        )
        doctype, attached_name, fieldname = "Item", target_name, "image"
    elif target_type == "category":
        category_is_owned = frappe.db.exists(
            "Item",
            {
                COMPANY_FIELD: company,
                "item_group": target_name,
            },
        )
        if not frappe.db.exists("Item Group", target_name) or not category_is_owned:
            frappe.throw(
                _("Category is not available for this business"),
                frappe.PermissionError,
            )
        category_images = _get_company_category_images(company)
        doctype, attached_name, fieldname = "Company", company, None
    else:
        frappe.throw(_("target_type must be 'item' or 'category'"))

    file_data = {
        "doctype": "File",
        "file_name": filename,
        "attached_to_doctype": doctype,
        "attached_to_name": attached_name,
        "is_private": 0,
        "content": content_base64,
        "decode": True,
    }
    if fieldname:
        file_data["attached_to_field"] = fieldname
    file_doc = frappe.get_doc(file_data)
    file_doc.flags.ignore_permissions = True
    file_doc.insert(ignore_permissions=True)

    if target_type == "category":
        category_images[target_name] = file_doc.file_url
        frappe.db.set_value(
            "Company",
            company,
            CATEGORY_IMAGES_FIELD,
            json.dumps(category_images, sort_keys=True),
        )
    else:
        # Bumping `modified` lets delta sync carry the new image to other
        # devices of the same business.
        frappe.db.set_value("Item", target_name, "image", file_doc.file_url)

    return {"image": file_doc.file_url}


def _get_company_category_images(company):
    raw = frappe.db.get_value("Company", company, CATEGORY_IMAGES_FIELD)
    if not raw:
        return {}
    try:
        values = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return {}
    if not isinstance(values, dict):
        return {}
    return {
        str(name): str(url)
        for name, url in values.items()
        if name and isinstance(url, str) and url
    }


def _require_document_company(
    doctype,
    name,
    company,
    *,
    company_field="company",
    label=None,
):
    """Reject a missing or cross-tenant Link without leaking its owner."""
    label = label or doctype
    owner = (
        frappe.db.get_value(doctype, name, company_field)
        if name
        else None
    )
    if owner != company:
        frappe.throw(
            _("{0} is not available for this business").format(label),
            frappe.PermissionError,
        )
    return name


def _get_user_company():
    """Resolve exactly one company from all of the user's tenant links."""
    user = frappe.session.user
    if user == "Guest":
        frappe.throw(_("Login required"), frappe.AuthenticationError)

    companies = set(
        frappe.get_all(
            "User Permission",
            filters={"user": user, "allow": "Company"},
            pluck="for_value",
            limit_page_length=0,
        )
    )
    profile_names = frappe.get_all(
        "POS Profile User",
        filters={"user": user, "parenttype": "POS Profile"},
        pluck="parent",
        limit_page_length=0,
    )
    if profile_names:
        companies.update(
            frappe.get_all(
                "POS Profile",
                filters={"name": ("in", profile_names)},
                pluck="company",
                limit_page_length=0,
            )
        )
    companies.discard(None)
    companies.discard("")

    if not companies:
        frappe.throw(_("No business is linked to this account yet"))
    if len(companies) != 1:
        frappe.throw(
            _("This account has conflicting business assignments"),
            frappe.PermissionError,
        )
    company = next(iter(companies))
    if not frappe.db.exists("Company", company):
        frappe.throw(_("The linked business no longer exists"))
    return company


def _get_pos_profile_for_company(profile_name, company, user):
    """Resolve an enabled POS Profile assigned to ``user`` and ``company``."""
    if profile_name:
        _require_document_company(
            "POS Profile", profile_name, company, label=_("POS Profile")
        )
        assigned = frappe.db.exists(
            "POS Profile User",
            {
                "parent": profile_name,
                "parenttype": "POS Profile",
                "user": user,
            },
        )
        if not assigned:
            frappe.throw(
                _("POS Profile is not assigned to this user"),
                frappe.PermissionError,
            )
    else:
        assigned_profiles = frappe.get_all(
            "POS Profile User",
            filters={
                "user": user,
                "parenttype": "POS Profile",
            },
            pluck="parent",
            limit_page_length=0,
        )
        candidates = (
            frappe.get_all(
                "POS Profile",
                filters={
                    "name": ("in", assigned_profiles),
                    "company": company,
                    "disabled": 0,
                },
                pluck="name",
                order_by="creation asc",
                limit_page_length=1,
            )
            if assigned_profiles
            else []
        )
        profile_name = candidates[0] if candidates else None

    if not profile_name:
        frappe.throw(_("No assigned POS Profile found for this business"))

    profile = frappe.get_cached_doc("POS Profile", profile_name)
    if profile.company != company or profile.disabled:
        frappe.throw(
            _("POS Profile is not available for this business"),
            frappe.PermissionError,
        )
    if not profile.customer or not frappe.db.exists("Customer", profile.customer):
        frappe.throw(_("The POS Profile has no valid customer"))
    if not profile.selling_price_list or not frappe.db.exists(
        "Price List", profile.selling_price_list
    ):
        frappe.throw(_("The POS Profile has no valid selling price list"))
    _require_document_company(
        "Warehouse", profile.warehouse, company, label=_("Warehouse")
    )
    return profile


def _ensure_item_group(name):
    """Item Group names are globally unique, so an existing group (even
    another tenant's) is reused — only the name is shared, items stay
    isolated via their company stamp."""
    if frappe.db.exists("Item Group", name):
        return name
    group = frappe.get_doc(
        {
            "doctype": "Item Group",
            "item_group_name": name,
            "parent_item_group": "All Item Groups",
            "is_group": 0,
        }
    )
    group.insert(ignore_permissions=True)
    return group.name


def _make_item_code(company, item_name):
    """Item codes are globally unique — namespace them per company so
    two shops can both sell "Chai"."""
    abbr = frappe.db.get_value("Company", company, "abbr") or "POS"
    base = frappe.scrub(item_name).replace("_", "-").strip("-")[:30] or "item"
    code = f"{abbr}-{base}".upper()
    candidate, counter = code, 1
    while frappe.db.exists("Item", candidate):
        counter += 1
        candidate = f"{code}-{counter}"
    return candidate


def _set_selling_price(item_code, rate, price_list=DEFAULT_PRICE_LIST):
    uom = frappe.db.get_value("Item", item_code, "stock_uom")
    existing = frappe.db.get_value(
        "Item Price",
        {
            "item_code": item_code,
            "price_list": price_list,
            "selling": 1,
            "uom": uom,
            "customer": ("is", "not set"),
            "batch_no": ("is", "not set"),
        },
        "name",
    )
    if existing:
        # update_modified stays True so delta sync picks the change up.
        frappe.db.set_value("Item Price", existing, "price_list_rate", rate)
    else:
        frappe.get_doc(
            {
                "doctype": "Item Price",
                "item_code": item_code,
                "price_list": price_list,
                "uom": uom,
                "selling": 1,
                "price_list_rate": rate,
            }
        ).insert(ignore_permissions=True)


# ---------------------------------------------------------------------------
# 2c. Shared register state
# ---------------------------------------------------------------------------

def _validate_register_id(register_id, user=None):
    register_id = (register_id or "").strip()
    if not register_id or len(register_id) > 140:
        frappe.throw(_("A valid register ID is required"))
    assigned = frappe.db.get_value("User", user or frappe.session.user, DEVICE_ID_FIELD)
    if assigned and assigned != register_id:
        frappe.throw(_("This register is not assigned to the current user"), frappe.PermissionError)
    return register_id


def _table_state_key(company, table_no):
    return "TABLE-" + hashlib.sha256(f"{company}\0{table_no}".encode()).hexdigest()[:32]


def _upsert_shared_table(company, table_no, status, offline_id, register_id):
    table_no = (table_no or "").strip()[:140]
    if not table_no:
        frappe.throw(_("Table number is required"))
    status = "Occupied" if str(status).lower() == "occupied" else "Free"
    name = _table_state_key(company, table_no)
    if frappe.db.exists("FlexiPOS Table", name):
        _require_document_company("FlexiPOS Table", name, company)
        frappe.db.set_value(
            "FlexiPOS Table",
            name,
            {
                "status": status,
                "current_offline_invoice_id": offline_id,
                "register_id": register_id,
            },
        )
    else:
        frappe.get_doc(
            {
                "doctype": "FlexiPOS Table",
                "state_key": name,
                "company": company,
                "table_no": table_no,
                "status": status,
                "current_offline_invoice_id": offline_id,
                "register_id": register_id,
            }
        ).insert(ignore_permissions=True)


@frappe.whitelist()
def sync_register_state(register_id, operations_json="[]"):
    """Merge offline register operations and return the company-wide state."""
    _require_any_screen_access("quick_sale", "held_orders", "tables", "kitchen", "shift")
    company = _get_user_company()
    register_id = _validate_register_id(register_id)
    operations = _json_list(operations_json, _("register operations"))
    if len(operations) > 500:
        frappe.throw(_("Too many register operations in one sync"))

    permissions = set(_screen_permissions_for_user(frappe.session.user))
    for operation in operations:
        if not isinstance(operation, dict):
            frappe.throw(_("Register operation must be an object"))
        action = operation.get("action")
        if not isinstance(action, str):
            frappe.throw(_("Register operation action is required"))
        payload = operation.get("payload") or {}
        if not isinstance(payload, dict):
            frappe.throw(_("Register operation payload must be an object"))
        if action.startswith("table_"):
            if not permissions.intersection({"quick_sale", "tables", "kitchen"}):
                frappe.throw(_("Not permitted to update tables"), frappe.PermissionError)
            _apply_table_operation(company, register_id, action, payload)
        elif action.startswith("held_"):
            if not permissions.intersection({"quick_sale", "held_orders"}):
                frappe.throw(_("Not permitted to update held orders"), frappe.PermissionError)
            _apply_held_operation(company, register_id, action, payload)
        elif action in ("shift_upsert", "movement_upsert"):
            if "shift" not in permissions:
                frappe.throw(_("Not permitted to update shifts"), frappe.PermissionError)
            _apply_shift_operation(company, register_id, action, payload)
        else:
            frappe.throw(_("Unknown register operation"))

    return _shared_register_state(company, register_id, include_shift="shift" in permissions)


def _apply_table_operation(company, register_id, action, payload):
    table_no = (payload.get("table_no") or "").strip()
    if action == "table_upsert":
        _upsert_shared_table(
            company,
            table_no,
            payload.get("status"),
            (payload.get("current_offline_invoice_id") or "").strip() or None,
            register_id,
        )
        return
    if action == "table_delete":
        name = _table_state_key(company, table_no)
        if frappe.db.exists("FlexiPOS Table", name):
            _require_document_company("FlexiPOS Table", name, company)
            frappe.delete_doc("FlexiPOS Table", name, ignore_permissions=True)
        return
    frappe.throw(_("Unknown table operation"))


def _apply_held_operation(company, register_id, action, payload):
    offline_id = (payload.get("id") or "").strip()
    if not offline_id or len(offline_id) > 140:
        frappe.throw(_("Held order ID is invalid"))
    existing = frappe.db.exists("FlexiPOS Held Order", offline_id)
    if existing:
        _require_document_company("FlexiPOS Held Order", offline_id, company)
    if action == "held_delete":
        if existing:
            frappe.delete_doc("FlexiPOS Held Order", offline_id, ignore_permissions=True)
        return
    if action != "held_upsert":
        frappe.throw(_("Unknown held-order operation"))
    lines = payload.get("lines")
    if not isinstance(lines, list) or not lines or len(lines) > 100:
        frappe.throw(_("Held order lines are invalid"))
    values = {
        "company": company,
        "register_id": register_id,
        "staff_name": (payload.get("staff_name") or "").strip()[:140],
        "order_type": payload.get("order_type") if payload.get("order_type") in ("Dine-in", "Takeaway", "Delivery") else "Dine-in",
        "table_no": (payload.get("table_no") or "").strip()[:140] or None,
        "grand_total": flt(payload.get("grand_total")),
        "item_count": flt(payload.get("item_count")),
        "lines_json": json.dumps(lines),
        "held_at": get_datetime(payload.get("held_at") or now_datetime()),
    }
    if existing:
        frappe.db.set_value("FlexiPOS Held Order", offline_id, values)
    else:
        frappe.get_doc(
            {"doctype": "FlexiPOS Held Order", "offline_id": offline_id, **values}
        ).insert(ignore_permissions=True)


def _apply_shift_operation(company, register_id, action, payload):
    if action == "movement_upsert":
        movement_id = (payload.get("movement_id") or "").strip()
        shift_id = (payload.get("shift_id") or "").strip()
        _require_document_company("FlexiPOS Shift", shift_id, company)
        shift_register = frappe.db.get_value("FlexiPOS Shift", shift_id, "register_id")
        if shift_register != register_id:
            frappe.throw(_("Shift belongs to another register"), frappe.PermissionError)
        existing = frappe.db.exists("FlexiPOS Cash Movement", movement_id)
        if existing:
            _require_document_company("FlexiPOS Cash Movement", movement_id, company)
            return
        movement_type = payload.get("type")
        if movement_type not in ("pay_in", "pay_out") or flt(payload.get("amount")) <= 0:
            frappe.throw(_("Cash movement is invalid"))
        frappe.get_doc(
            {
                "doctype": "FlexiPOS Cash Movement",
                "movement_id": movement_id,
                "company": company,
                "register_id": register_id,
                "shift": shift_id,
                "movement_type": "Pay In" if movement_type == "pay_in" else "Pay Out",
                "amount": flt(payload.get("amount")),
                "note": (payload.get("note") or "").strip()[:500],
                "created_at": get_datetime(payload.get("created_at") or now_datetime()),
            }
        ).insert(ignore_permissions=True)
        return

    shift_id = (payload.get("id") or "").strip()
    if not shift_id:
        frappe.throw(_("Shift ID is required"))
    existing = frappe.db.exists("FlexiPOS Shift", shift_id)
    if existing:
        _require_document_company("FlexiPOS Shift", shift_id, company)
        if frappe.db.get_value("FlexiPOS Shift", shift_id, "register_id") != register_id:
            frappe.throw(_("Shift belongs to another register"), frappe.PermissionError)
    status = "Closed" if payload.get("status") == "closed" else "Open"
    if status == "Open" and not existing and frappe.db.exists(
        "FlexiPOS Shift", {"company": company, "register_id": register_id, "status": "Open"}
    ):
        frappe.throw(_("This register already has an open shift"))
    values = {
        "company": company,
        "register_id": register_id,
        "staff_user": frappe.session.user,
        "opening_float": max(flt(payload.get("opening_float")), 0),
        "opened_at": get_datetime(payload.get("opened_at") or now_datetime()),
        "closed_at": get_datetime(payload.get("closed_at")) if payload.get("closed_at") else None,
        "counted_amount": flt(payload.get("counted_amount")) if payload.get("counted_amount") is not None else None,
        "status": status,
    }
    if existing:
        frappe.db.set_value("FlexiPOS Shift", shift_id, values)
    else:
        frappe.get_doc(
            {"doctype": "FlexiPOS Shift", "shift_id": shift_id, **values}
        ).insert(ignore_permissions=True)


def _shared_register_state(company, register_id, include_shift=False):
    tables = frappe.get_all(
        "FlexiPOS Table",
        filters={"company": company},
        fields=["table_no", "status", "current_offline_invoice_id", "register_id"],
        order_by="table_no",
        limit_page_length=0,
    )
    held = frappe.get_all(
        "FlexiPOS Held Order",
        filters={"company": company},
        fields=["offline_id", "order_type", "table_no", "staff_name", "grand_total", "item_count", "lines_json", "held_at", "register_id"],
        order_by="held_at",
        limit_page_length=0,
    )
    result = {
        "tables": [
            {**dict(row), "status": row.status.lower()} for row in tables
        ],
        "held_orders": [
            {
                "id": row.offline_id,
                "order_type": row.order_type,
                "table_no": row.table_no,
                "staff_name": row.staff_name,
                "grand_total": flt(row.grand_total),
                "item_count": flt(row.item_count),
                "lines": json.loads(row.lines_json or "[]"),
                "held_at": str(row.held_at),
                "register_id": row.register_id,
            }
            for row in held
        ],
        "kitchen_orders": _shared_kitchen_orders(company),
        "shifts": [],
        "cash_movements": [],
    }
    if include_shift:
        shifts = frappe.get_all(
            "FlexiPOS Shift",
            filters={"company": company, "register_id": register_id},
            fields=["shift_id", "staff_user", "opening_float", "opened_at", "closed_at", "counted_amount", "status", "register_id"],
            order_by="opened_at desc",
            limit_page_length=100,
        )
        result["shifts"] = [
            {
                "id": row.shift_id,
                "staff_name": row.staff_user,
                "register_id": row.register_id,
                "opening_float": flt(row.opening_float),
                "opened_at": str(row.opened_at),
                "closed_at": str(row.closed_at) if row.closed_at else None,
                "counted_amount": flt(row.counted_amount) if row.counted_amount is not None else None,
                "status": row.status.lower(),
            }
            for row in shifts
        ]
        shift_ids = [row.shift_id for row in shifts]
        movements = frappe.get_all(
            "FlexiPOS Cash Movement",
            filters={"shift": ("in", shift_ids)},
            fields=["movement_id", "shift", "movement_type", "amount", "note", "created_at", "register_id"],
            order_by="created_at",
            limit_page_length=0,
        ) if shift_ids else []
        result["cash_movements"] = [
            {
                "movement_id": row.movement_id,
                "shift_id": row.shift,
                "type": "pay_in" if row.movement_type == "Pay In" else "pay_out",
                "amount": flt(row.amount),
                "note": row.note,
                "created_at": str(row.created_at),
                "register_id": row.register_id,
            }
            for row in movements
        ]
    return result


def _shared_kitchen_orders(company):
    invoices = frappe.get_all(
        "Sales Invoice",
        filters={"company": company, "docstatus": 1, KITCHEN_STATUS_FIELD: ("in", ["Placed", "Preparing", "Ready"])},
        fields=["name", OFFLINE_ID_FIELD, ORDER_TYPE_FIELD, TABLE_FIELD, KITCHEN_STATUS_FIELD, REGISTER_ID_FIELD, "customer", "posting_date", "posting_time", "net_total", "total_taxes_and_charges", "grand_total", "paid_amount"],
        order_by="posting_date, posting_time",
        limit_page_length=0,
    )
    if not invoices:
        return []
    names = [row.name for row in invoices]
    item_rows = frappe.get_all(
        "Sales Invoice Item",
        filters={"parent": ("in", names), "parenttype": "Sales Invoice"},
        fields=["parent", "item_code", "item_name", "qty", "rate", "idx"],
        order_by="parent, idx",
        limit_page_length=0,
    )
    item_codes = {row.item_code for row in item_rows}
    taxes = {
        row.name: flt(row.get(TAX_RATE_FIELD))
        for row in frappe.get_all(
            "Item",
            filters={"name": ("in", list(item_codes))},
            fields=["name", TAX_RATE_FIELD],
            limit_page_length=0,
        )
    } if item_codes else {}
    by_invoice = {}
    for row in item_rows:
        by_invoice.setdefault(row.parent, []).append(
            {
                "item_code": row.item_code,
                "item_name": row.item_name,
                "qty": flt(row.qty),
                "rate": flt(row.rate),
                "tax_rate": taxes.get(row.item_code, 0),
            }
        )
    payments = {
        row.parent: row.mode_of_payment
        for row in frappe.get_all(
            "Sales Invoice Payment",
            filters={"parent": ("in", names), "parenttype": "Sales Invoice"},
            fields=["parent", "mode_of_payment"],
            order_by="parent, idx",
            limit_page_length=0,
        )
    }
    return [
        {
            "offline_invoice_id": row.get(OFFLINE_ID_FIELD) or f"server:{row.name}",
            "erp_invoice_name": row.name,
            "customer": row.customer,
            "posting_datetime": f"{row.posting_date} {row.posting_time}",
            "order_type": row.get(ORDER_TYPE_FIELD),
            "table_no": row.get(TABLE_FIELD),
            "kitchen_status": row.get(KITCHEN_STATUS_FIELD),
            "register_id": row.get(REGISTER_ID_FIELD),
            "server_net_total": flt(row.net_total),
            "server_tax_total": flt(row.total_taxes_and_charges),
            "server_grand_total": flt(row.grand_total),
            "paid_amount": flt(row.paid_amount),
            "payment_mode": payments.get(row.name, "Cash"),
            "items": by_invoice.get(row.name, []),
        }
        for row in invoices
    ]


# ---------------------------------------------------------------------------
# 3. push_offline_invoices
# ---------------------------------------------------------------------------

@frappe.whitelist()
def push_offline_invoices(invoices_json):
    """Accept offline sales from the client and create submitted POS
    Sales Invoices.

    Each invoice payload:
        {
          "offline_invoice_id": "uuid",            # required, idempotency key
          "company": "My Shop",                    # required
          "pos_profile": "My Shop POS",            # optional, resolved if absent
          "customer": "Walk-in Customer",          # optional
          "posting_datetime": "2026-07-05 14:03:22",
          "items": [
            {
              "item_code": "X",
              "qty": 2,
              "rate": 150.0,          # unit price INCLUDING chosen modifiers
              "modifiers": [{"group": "Size", "label": "Large", "price": 50}]
            }
          ],
          "payments": [{"mode_of_payment": "Cash", "amount": 300.0}]
        }

    Modifiers have no item_code of their own (see module docstring) — the
    client resolves the chosen options' prices into `rate` itself, and
    `modifiers` here is carried through only to annotate the invoice
    line's description for the kitchen ticket/receipt.

    Small batches are processed inline so the client gets a per-invoice
    result immediately; large batches are queued to a background worker
    and confirmed on the next sync (the unique offline id makes the
    retry a no-op duplicate).
    """
    _require_screen_access("quick_sale")
    invoices = invoices_json
    if isinstance(invoices, str):
        try:
            invoices = json.loads(invoices)
        except json.JSONDecodeError:
            frappe.throw(_("invoices_json is not valid JSON"))
    if not isinstance(invoices, list) or not invoices:
        frappe.throw(_("Expected a non-empty list of invoices"))

    _ensure_custom_fields()
    # Tenant guard: a device may only book sales into its own company.
    allowed_company = _get_user_company()

    if len(invoices) > INLINE_BATCH_LIMIT:
        frappe.enqueue(
            _process_invoice_batch,
            queue="long",
            job_name=f"flexipos_push_{frappe.session.user}",
            invoices=invoices,
            user=frappe.session.user,
            allowed_company=allowed_company,
        )
        return {"queued": True, "count": len(invoices), "results": []}

    results = _process_invoice_batch(
        invoices, frappe.session.user, allowed_company
    )
    return {
        "queued": False,
        "count": len(invoices),
        "results": results,
        "synced": sum(1 for r in results if r["status"] in ("success", "duplicate")),
        "failed": sum(1 for r in results if r["status"] == "failed"),
    }


def _process_invoice_batch(invoices, user, allowed_company=None):
    """Create one Sales Invoice per payload, isolating each in a savepoint
    so a single bad invoice cannot poison the batch."""
    results = []
    for payload in invoices:
        if not isinstance(payload, dict):
            results.append(
                {
                    "offline_invoice_id": None,
                    "status": "failed",
                    "error": "Invoice payload must be an object",
                }
            )
            continue
        offline_id = (payload.get("offline_invoice_id") or "").strip()
        if not offline_id:
            results.append(
                {
                    "offline_invoice_id": None,
                    "status": "failed",
                    "error": "offline_invoice_id missing",
                }
            )
            continue

        if allowed_company and payload.get("company") != allowed_company:
            results.append(
                {
                    "offline_invoice_id": offline_id,
                    "status": "failed",
                    "error": "Not permitted for this company",
                }
            )
            continue

        existing = frappe.db.get_value(
            "Sales Invoice",
            {
                OFFLINE_ID_FIELD: offline_id,
                "company": allowed_company,
            },
            "name",
        )
        if existing:
            totals = frappe.db.get_value(
                "Sales Invoice",
                existing,
                ["net_total", "total_taxes_and_charges", "grand_total"],
                as_dict=True,
            )
            results.append(
                {
                    "offline_invoice_id": offline_id,
                    "status": "duplicate",
                    "invoice": existing,
                    "net_total": flt(totals.net_total),
                    "tax_total": flt(totals.total_taxes_and_charges),
                    "grand_total": flt(totals.grand_total),
                }
            )
            continue

        savepoint = "flexipos_invoice"
        frappe.db.savepoint(savepoint)
        try:
            doc = _create_pos_invoice(
                payload,
                offline_id,
                user=user,
                allowed_company=allowed_company,
            )
            results.append(
                {
                    "offline_invoice_id": offline_id,
                    "status": "success",
                    "invoice": doc.name,
                    "net_total": flt(doc.net_total),
                    "tax_total": flt(doc.total_taxes_and_charges),
                    "grand_total": flt(doc.grand_total),
                }
            )
        except Exception as e:
            frappe.db.rollback(save_point=savepoint)
            frappe.log_error(
                title=f"FlexiPOS: offline invoice {offline_id} failed",
                message=f"user: {user}\npayload: {json.dumps(payload, default=str)}\n\n"
                + frappe.get_traceback(),
            )
            results.append(
                {
                    "offline_invoice_id": offline_id,
                    "status": "failed",
                    "error": str(e)[:300],
                }
            )
    return results


def _get_authoritative_item_price(
    item_code,
    price_list,
    uom,
    customer,
    posting_date,
):
    """Return the applicable server Item Price, never a client-provided rate."""
    rows = frappe.get_all(
        "Item Price",
        filters={
            "item_code": item_code,
            "price_list": price_list,
            "selling": 1,
        },
        fields=[
            "name",
            "price_list_rate",
            "uom",
            "customer",
            "batch_no",
            "valid_from",
            "valid_upto",
            "modified",
        ],
        order_by="valid_from desc, modified desc",
        limit_page_length=0,
    )
    posting_date = str(posting_date)
    candidates = []
    for row in rows:
        if row.uom and row.uom != uom:
            continue
        if row.customer and row.customer != customer:
            continue
        if row.batch_no:
            continue
        if row.valid_from and str(row.valid_from) > posting_date:
            continue
        if row.valid_upto and str(row.valid_upto) < posting_date:
            continue
        candidates.append(row)

    if not candidates:
        frappe.throw(
            _("No active selling price exists for item {0}").format(item_code)
        )

    # Customer-specific prices outrank generic rows; the query order then
    # picks the newest effective price within that class.
    candidates.sort(key=lambda row: 0 if row.customer == customer else 1)
    rate = flt(candidates[0].price_list_rate)
    if not math.isfinite(rate) or rate < 0:
        frappe.throw(_("The selling price for item {0} is invalid").format(item_code))
    return rate


def _resolve_authoritative_modifiers(item_code, company, requested):
    """Validate selections against groups assigned to the item and re-price them."""
    if requested is None:
        requested = []
    if not isinstance(requested, list):
        frappe.throw(_("Item modifiers must be a list"))

    links = frappe.get_all(
        "FlexiPOS Item Modifier Group",
        filters={"parent": item_code, "parenttype": "Item"},
        fields=["modifier_group", "idx"],
        order_by="idx",
        limit_page_length=0,
    )
    groups = []
    by_key = {}
    for link in links:
        group = frappe.get_cached_doc("FlexiPOS Modifier Group", link.modifier_group)
        if group.flexipos_company != company:
            frappe.throw(
                _("An assigned modifier group is not available for this business"),
                frappe.PermissionError,
            )
        groups.append(group)
        by_key[group.name] = group
        by_key[group.group_name] = group

    selected_by_group = {group.name: [] for group in groups}
    seen = set()
    resolved = []
    for value in requested:
        if not isinstance(value, dict):
            frappe.throw(_("Each modifier must be an object"))
        group_key = (value.get("group") or "").strip()
        label = (value.get("label") or "").strip()
        group = by_key.get(group_key)
        if not group or not label:
            frappe.throw(_("A selected modifier is not available for this item"))
        key = (group.name, label)
        if key in seen:
            frappe.throw(_("The same modifier cannot be selected twice"))
        matches = [option for option in group.options if option.label == label]
        if len(matches) != 1:
            frappe.throw(_("A selected modifier is not available for this item"))
        seen.add(key)
        option = matches[0]
        selected_by_group[group.name].append(option)
        resolved.append(
            {
                "group": group.group_name,
                "label": option.label,
                "price": flt(option.price),
            }
        )

    for group in groups:
        count = len(selected_by_group[group.name])
        minimum = max(cint(group.min_select), 1 if group.required else 0)
        maximum = cint(group.max_select)
        if group.selection_type == "Single" and count > 1:
            frappe.throw(_("Choose only one option from {0}").format(group.group_name))
        if count < minimum:
            frappe.throw(_("Choose at least {0} option(s) from {1}").format(minimum, group.group_name))
        if maximum and count > maximum:
            frappe.throw(_("Choose no more than {0} option(s) from {1}").format(maximum, group.group_name))

    return resolved


def _get_output_tax_account(company):
    account = frappe.db.get_value(
        "Account",
        {
            "company": company,
            "account_name": "FlexiPOS Output Tax",
            "account_type": "Tax",
            "is_group": 0,
            "disabled": 0,
        },
    )
    if account:
        return account

    from erpnext.setup.setup_wizard.operations.taxes_setup import (
        get_or_create_account,
    )

    return get_or_create_account(
        company,
        {
            "account_name": "FlexiPOS Output Tax",
            "root_type": "Liability",
        },
    ).name


def _estimate_matches(server_value, client_value, tolerance=PRICE_TOLERANCE):
    client_value = flt(client_value)
    return math.isfinite(client_value) and abs(server_value - client_value) <= tolerance


def _create_pos_invoice(payload, offline_id, *, user, allowed_company):
    company = (payload.get("company") or "").strip()
    if not company or company != allowed_company:
        frappe.throw(
            _("Company is not available for this user"),
            frappe.PermissionError,
        )

    profile = _get_pos_profile_for_company(
        (payload.get("pos_profile") or "").strip() or None,
        company,
        user,
    )
    register_id = (payload.get("register_id") or "").strip()
    if not register_id:
        register_id = frappe.db.get_value("User", user, DEVICE_ID_FIELD)
    register_id = _validate_register_id(register_id, user=user)

    requested_customer = (payload.get("customer") or "").strip()
    if requested_customer and requested_customer != profile.customer:
        frappe.throw(
            _("Customer is not available for this POS Profile"),
            frappe.PermissionError,
        )

    items = payload.get("items") or []
    if not isinstance(items, list) or not items:
        frappe.throw(_("Invoice has no items"))

    item_codes = {
        (row.get("item_code") or "").strip()
        for row in items
        if isinstance(row, dict) and row.get("item_code")
    }
    item_rows = frappe.get_all(
        "Item",
        filters={"name": ("in", list(item_codes))},
        fields=["name", COMPANY_FIELD, "disabled", "stock_uom", TAX_RATE_FIELD],
        limit_page_length=0,
    ) if item_codes else []
    owned_items = {row.name: row for row in item_rows}

    server_now = now_datetime()
    posting = get_datetime(payload.get("posting_datetime") or server_now)
    if posting > add_to_date(server_now, minutes=5) or posting < add_to_date(
        server_now, days=-30
    ):
        frappe.throw(_("Sale time is outside the allowed offline window"))
    order_type = payload.get("order_type")
    # Only Dine-in/Takeaway orders go through the kitchen; Delivery
    # (or no order type at all, e.g. non-restaurant businesses) skip it.
    kitchen_status = "Placed" if order_type in ("Dine-in", "Takeaway") else None

    doc = frappe.new_doc("Sales Invoice")
    doc.flags.ignore_pricing_rule = True
    doc.update(
        {
            "company": company,
            "customer": profile.customer,
            "is_pos": 1,
            "pos_profile": profile.name,
            "set_posting_time": 1,
            "posting_date": posting.date(),
            "posting_time": posting.time(),
            "due_date": posting.date(),
            "update_stock": cint(profile.update_stock),
            "selling_price_list": profile.selling_price_list,
            OFFLINE_ID_FIELD: offline_id,
            ORDER_TYPE_FIELD: order_type,
            TABLE_FIELD: payload.get("table_no"),
            KITCHEN_STATUS_FIELD: kitchen_status,
            REGISTER_ID_FIELD: register_id,
        }
    )
    branch = (payload.get("branch") or "").strip()
    if branch:
        if not frappe.get_meta("Sales Invoice").has_field("branch"):
            frappe.throw(_("Branch accounting is not enabled for Sales Invoice"))
        _require_document_company(
            "Branch",
            branch,
            company,
            company_field=BRANCH_COMPANY_FIELD,
            label=_("Branch"),
        )
        doc.branch = branch

    authoritative_lines = []
    client_gross = 0
    server_gross = 0
    for row in items:
        if not isinstance(row, dict):
            frappe.throw(_("Invoice item must be an object"))
        item_code = (row.get("item_code") or "").strip()
        item = owned_items.get(item_code)
        if not item or item.get(COMPANY_FIELD) != company:
            frappe.throw(
                _("Item is not available for this business"),
                frappe.PermissionError,
            )
        if item.disabled:
            frappe.throw(_("Item {0} is disabled").format(item_code))
        qty = flt(row.get("qty"))
        if not math.isfinite(qty) or qty <= 0:
            frappe.throw(_("Quantity for item {0} must be greater than zero").format(item_code))
        base_rate = _get_authoritative_item_price(
            item_code,
            profile.selling_price_list,
            item.stock_uom,
            profile.customer,
            server_now.date(),
        )
        modifiers = _resolve_authoritative_modifiers(
            item_code, company, row.get("modifiers")
        )
        server_rate = base_rate + sum(flt(m["price"]) for m in modifiers)
        if not math.isfinite(server_rate) or server_rate < 0:
            frappe.throw(_("The total price for item {0} is invalid").format(item_code))
        if "rate" not in row or not _estimate_matches(server_rate, row.get("rate")):
            frappe.throw(
                _("Price changed for {0}. Refresh the catalog and retry the sale.").format(item_code)
            )
        tax_rate = flt(item.get(TAX_RATE_FIELD))
        if not math.isfinite(tax_rate) or tax_rate < 0 or tax_rate > 100:
            frappe.throw(_("The tax rate for item {0} is invalid").format(item_code))
        if "tax_rate" in row and not _estimate_matches(
            tax_rate, row.get("tax_rate"), TAX_RATE_TOLERANCE
        ):
            frappe.throw(
                _("Tax changed for {0}. Refresh the catalog and retry the sale.").format(item_code)
            )
        client_gross += flt(row.get("rate")) * qty
        server_gross += server_rate * qty
        description = (
            ", ".join(
                f"{m.get('label')}"
                + (f" (+{flt(m.get('price'))})" if flt(m.get("price")) else "")
                for m in modifiers
                if isinstance(m, dict) and m.get("label")
            )
            if modifiers
            else None
        )
        doc.append(
            "items",
            {
                "item_code": item_code,
                "qty": qty,
                "rate": server_rate,
                "uom": item.stock_uom,
                "warehouse": profile.warehouse,
                **({"description": description} if description else {}),
            },
        )
        authoritative_lines.append(
            {"rate": server_rate, "tax_rate": tax_rate}
        )

    if not _estimate_matches(server_gross, client_gross):
        frappe.throw(_("Sale total changed. Refresh the catalog and retry the sale."))

    doc.set_missing_values()

    # set_missing_values may apply profile taxes or pricing rules. Replace
    # both with the already resolved company-owned price/tax records.
    has_tax = any(line["tax_rate"] > 0 for line in authoritative_lines)
    tax_account = _get_output_tax_account(company) if has_tax else None
    for invoice_item, line in zip(doc.items, authoritative_lines, strict=True):
        invoice_item.price_list_rate = line["rate"]
        invoice_item.rate = line["rate"]
        invoice_item.discount_percentage = 0
        invoice_item.discount_amount = 0
        invoice_item.item_tax_rate = (
            json.dumps({tax_account: line["tax_rate"]}) if tax_account else "{}"
        )

    doc.set("taxes", [])
    if tax_account:
        doc.append(
            "taxes",
            {
                "charge_type": "On Net Total",
                "account_head": tax_account,
                "description": _("Tax included in selling price"),
                "rate": 0,
                "included_in_print_rate": 1,
            },
        )

    doc.run_method("calculate_taxes_and_totals")

    payments = payload.get("payments") or []
    doc.set("payments", [])
    if not isinstance(payments, list) or len(payments) > 1:
        frappe.throw(_("FlexiPOS sales require exactly one payment mode"))
    allowed_payment_modes = [
        row.mode_of_payment for row in profile.payments if row.mode_of_payment
    ]
    if not allowed_payment_modes:
        frappe.throw(_("The POS Profile has no payment mode"))
    payment = payments[0] if payments else {}
    if not isinstance(payment, dict):
        frappe.throw(_("Payment must be an object"))
    mode = (payment.get("mode_of_payment") or allowed_payment_modes[0]).strip()
    if mode not in allowed_payment_modes:
        frappe.throw(
            _("Payment mode is not available for this POS Profile"),
            frappe.PermissionError,
        )
    payable = flt(doc.rounded_total or doc.grand_total)
    doc.append("payments", {"mode_of_payment": mode, "amount": payable})

    doc.flags.ignore_permissions = True
    doc.insert()
    doc.submit()
    if doc.get(TABLE_FIELD) and order_type == "Dine-in":
        _upsert_shared_table(
            company,
            doc.get(TABLE_FIELD),
            "Occupied",
            offline_id,
            register_id,
        )
    return doc


@frappe.whitelist()
def update_kitchen_status(invoice_name, status):
    """Advance an order's kitchen status from the Kitchen Display Screen.

    Best-effort from the client's point of view — kitchen status lives
    primarily in the device's local SQLite; this endpoint just mirrors
    it back to the Sales Invoice so other devices/reports can see it.
    """
    _require_screen_access("kitchen")
    status = (status or "").strip()
    if status not in KITCHEN_STATUSES:
        frappe.throw(_("Invalid kitchen status"))

    company = _get_user_company()
    _require_document_company(
        "Sales Invoice", invoice_name, company, label=_("Order")
    )

    frappe.db.set_value(
        "Sales Invoice", invoice_name, KITCHEN_STATUS_FIELD, status, update_modified=False
    )
    table_no = frappe.db.get_value("Sales Invoice", invoice_name, TABLE_FIELD)
    if table_no:
        register_id = frappe.db.get_value("Sales Invoice", invoice_name, REGISTER_ID_FIELD)
        _upsert_shared_table(
            company,
            table_no,
            "Free" if status == "Served" else "Occupied",
            None if status == "Served" else frappe.db.get_value("Sales Invoice", invoice_name, OFFLINE_ID_FIELD),
            register_id,
        )
    return {"invoice": invoice_name, "kitchen_status": status}


# ---------------------------------------------------------------------------
# 3b. Refunds
# ---------------------------------------------------------------------------
# Line-item precise refunds map onto ERPNext's standard Credit Note
# mechanism (Sales Invoice with is_return=1, return_against=<original>,
# negative quantities) — no custom refund/transaction DocType needed.
# The refund always returns to the original invoice's tender (the new
# Sales Invoice Payment row reuses the same mode_of_payment), and the
# reason is recorded in the credit note's remarks for the audit trail.

@frappe.whitelist()
def process_refund(invoice_name, items_json, reason=None):
    """Refund one or more line items from a submitted Sales Invoice.

    Payload:
        invoice_name: "ACC-SINV-2026-00078"
        items_json: [{"item_code": "X", "qty": 1}]   # qty being returned
        reason: "Wrong item served"                    # optional, freeform

    Returns the new credit note's name and the refunded amount. Fails
    if the invoice belongs to another business, isn't submitted, or a
    requested item/qty exceeds what was actually sold (accounting for
    any prior partial refunds against the same invoice).
    """
    _require_screen_access("order_history")
    items = items_json
    if isinstance(items, str):
        try:
            items = json.loads(items)
        except json.JSONDecodeError:
            frappe.throw(_("items_json is not valid JSON"))
    if not isinstance(items, list) or not items:
        frappe.throw(_("Select at least one item to refund"))

    company = _get_user_company()
    _require_document_company(
        "Sales Invoice", invoice_name, company, label=_("Order")
    )
    original = frappe.get_doc("Sales Invoice", invoice_name)
    if original.docstatus != 1:
        frappe.throw(_("Only submitted orders can be refunded"))
    if original.is_return:
        frappe.throw(_("This is already a credit note"))
    if original.pos_profile:
        _require_document_company(
            "POS Profile",
            original.pos_profile,
            company,
            label=_("POS Profile"),
        )

    sold_qty = {row.item_code: flt(row.qty) for row in original.items}
    already_refunded = _refunded_qty_by_item(invoice_name, company)

    return_rows = []
    for row in items:
        if not isinstance(row, dict):
            continue
        item_code = (row.get("item_code") or "").strip()
        qty = flt(row.get("qty"))
        if not item_code or qty <= 0:
            continue
        _require_document_company(
            "Item",
            item_code,
            company,
            company_field=COMPANY_FIELD,
            label=_("Item"),
        )
        available = sold_qty.get(item_code, 0) - already_refunded.get(item_code, 0)
        if qty > available:
            frappe.throw(
                _("Cannot refund {0} of {1} — only {2} left to refund").format(
                    qty, item_code, available
                )
            )
        return_rows.append((item_code, qty))

    if not return_rows:
        frappe.throw(_("Select at least one item to refund"))

    credit_note = frappe.new_doc("Sales Invoice")
    credit_note.update(
        {
            "company": original.company,
            "customer": original.customer,
            "is_pos": original.is_pos,
            "pos_profile": original.pos_profile,
            "is_return": 1,
            "return_against": original.name,
            "set_posting_time": 1,
            "posting_date": now_datetime().date(),
            "posting_time": now_datetime().time(),
            "update_stock": original.update_stock,
            "selling_price_list": original.selling_price_list,
            "remarks": f"Refund — {reason.strip()}" if reason and reason.strip() else "Refund",
            ORDER_TYPE_FIELD: original.get(ORDER_TYPE_FIELD),
            TABLE_FIELD: original.get(TABLE_FIELD),
        }
    )

    original_rows = {row.item_code: row for row in original.items}
    refund_total = 0.0
    for item_code, qty in return_rows:
        source_row = original_rows[item_code]
        if source_row.warehouse:
            _require_document_company(
                "Warehouse",
                source_row.warehouse,
                company,
                label=_("Warehouse"),
            )
        credit_note.append(
            "items",
            {
                "item_code": item_code,
                "qty": -qty,
                "rate": flt(source_row.rate),
                "uom": source_row.uom,
                "warehouse": source_row.warehouse,
                "description": source_row.description,
            },
        )
        refund_total += flt(source_row.rate) * qty

    credit_note.set_missing_values()
    credit_note.run_method("calculate_taxes_and_totals")

    original_tender = (
        original.payments[0].mode_of_payment if original.payments else "Cash"
    )
    credit_note.set("payments", [])
    credit_note.append(
        "payments",
        {"mode_of_payment": original_tender, "amount": flt(credit_note.grand_total)},
    )

    credit_note.flags.ignore_permissions = True
    credit_note.insert()
    credit_note.submit()

    return {
        "credit_note": credit_note.name,
        "refund_amount": flt(-credit_note.grand_total),
        "tender": original_tender,
    }


def _refunded_qty_by_item(invoice_name, company):
    """Sum of already-refunded quantities per item across every credit
    note issued against this invoice, so repeated partial refunds can't
    together exceed what was sold."""
    credit_notes = frappe.get_all(
        "Sales Invoice",
        filters={
            "return_against": invoice_name,
            "company": company,
            "docstatus": 1,
            "is_return": 1,
        },
        pluck="name",
    )
    if not credit_notes:
        return {}
    rows = frappe.get_all(
        "Sales Invoice Item",
        filters={"parent": ("in", credit_notes)},
        fields=["item_code", "qty"],
    )
    totals = {}
    for row in rows:
        # Credit note quantities are stored negative; flip sign for a
        # positive "amount already refunded" tally.
        totals[row.item_code] = totals.get(row.item_code, 0) - flt(row.qty)
    return totals


@frappe.whitelist()
def get_order_history(limit=100):
    """Recent submitted orders for the caller's business, newest first,
    with refund status derived from any credit notes against them —
    for the Order History & Refunds screen."""
    _require_screen_access("order_history")
    company = _get_user_company()
    invoices = frappe.get_all(
        "Sales Invoice",
        filters={"company": company, "docstatus": 1, "is_return": 0},
        fields=[
            "name",
            "posting_date",
            "posting_time",
            "grand_total",
            "customer",
            TABLE_FIELD,
            ORDER_TYPE_FIELD,
        ],
        order_by="posting_date desc, posting_time desc",
        limit_page_length=cint(limit),
    )
    if not invoices:
        return {"orders": []}

    names = [inv.name for inv in invoices]
    item_rows = frappe.get_all(
        "Sales Invoice Item",
        filters={"parent": ("in", names)},
        fields=["parent", "item_code", "item_name", "qty", "rate"],
    )
    items_by_invoice = {}
    for row in item_rows:
        items_by_invoice.setdefault(row.parent, []).append(
            {
                "item_code": row.item_code,
                "item_name": row.item_name,
                "qty": flt(row.qty),
                "rate": flt(row.rate),
            }
        )

    payment_rows = frappe.get_all(
        "Sales Invoice Payment",
        filters={"parent": ("in", names)},
        fields=["parent", "mode_of_payment"],
    )
    tender_by_invoice = {row.parent: row.mode_of_payment for row in payment_rows}

    credit_notes = frappe.get_all(
        "Sales Invoice",
        filters={"return_against": ("in", names), "docstatus": 1, "is_return": 1},
        fields=["return_against", "grand_total"],
    )
    refunded_by_invoice = {}
    for cn in credit_notes:
        refunded_by_invoice[cn.return_against] = refunded_by_invoice.get(
            cn.return_against, 0
        ) + abs(flt(cn.grand_total))

    orders = []
    for inv in invoices:
        refunded = refunded_by_invoice.get(inv.name, 0)
        if refunded <= 0:
            status = "paid"
        elif refunded >= flt(inv.grand_total):
            status = "refunded"
        else:
            status = "partial"
        orders.append(
            {
                "name": inv.name,
                "posting_date": str(inv.posting_date),
                "posting_time": str(inv.posting_time),
                "grand_total": flt(inv.grand_total),
                "customer": inv.customer,
                "table_no": inv.get(TABLE_FIELD),
                "order_type": inv.get(ORDER_TYPE_FIELD),
                "tender": tender_by_invoice.get(inv.name, "Cash"),
                "items": items_by_invoice.get(inv.name, []),
                "refund_status": status,
                "refunded_amount": refunded,
            }
        )
    return {"orders": orders}


# ---------------------------------------------------------------------------
# 4. PIN login
# ---------------------------------------------------------------------------

@frappe.whitelist()
def register_device_pin(pin, device_id):
    """Called once from a logged-in session to bind this device + PIN to
    the current user, enabling verify_pin_login afterwards."""
    pin = (pin or "").strip()
    device_id = (device_id or "").strip()
    if not pin.isdigit() or not 4 <= len(pin) <= 6:
        frappe.throw(_("PIN must be 4-6 digits"))
    if not device_id:
        frappe.throw(_("device_id is required"))

    salt = secrets.token_hex(16)
    frappe.db.set_value(
        "User",
        frappe.session.user,
        {
            PIN_HASH_FIELD: f"{salt}${_hash_pin(pin, salt)}",
            DEVICE_ID_FIELD: device_id,
        },
        update_modified=False,
    )
    return {"registered": True, "user": frappe.session.user}


@frappe.whitelist(allow_guest=True)
def verify_pin_login(pin, device_id):
    """Fast cashier unlock: verify the PIN registered for this device and
    open a session for the matching user. Rate-limited per device."""
    pin = (pin or "").strip()
    device_id = (device_id or "").strip()
    if not pin or not device_id:
        frappe.throw(_("PIN and device_id are required"), frappe.AuthenticationError)

    cache_key = f"flexipos_pin_attempts:{device_id}"
    attempts = cint(frappe.cache().get_value(cache_key))
    if attempts >= MAX_PIN_ATTEMPTS:
        frappe.throw(
            _("Too many attempts. Try again in a few minutes."),
            frappe.AuthenticationError,
        )

    user = frappe.db.get_value(
        "User",
        {DEVICE_ID_FIELD: device_id, "enabled": 1},
        ["name", PIN_HASH_FIELD],
        as_dict=True,
    )

    verified = False
    if user and user.get(PIN_HASH_FIELD) and "$" in user[PIN_HASH_FIELD]:
        salt, stored_hash = user[PIN_HASH_FIELD].split("$", 1)
        verified = secrets.compare_digest(_hash_pin(pin, salt), stored_hash)

    if not verified:
        frappe.cache().set_value(
            cache_key, attempts + 1, expires_in_sec=PIN_LOCKOUT_SECONDS
        )
        frappe.throw(_("Invalid PIN"), frappe.AuthenticationError)

    frappe.cache().delete_value(cache_key)
    frappe.local.login_manager.login_as(user.name)
    business = get_my_business()
    return {
        "user": user.name,
        "full_name": frappe.db.get_value("User", user.name, "full_name"),
        "sid": frappe.session.sid,
        **_get_api_credentials(user.name),
        **business,
    }


def _hash_pin(pin, salt):
    return hashlib.pbkdf2_hmac("sha256", pin.encode(), salt.encode(), 60_000).hex()


# ---------------------------------------------------------------------------
# 4b. Team & roles (admin-only staff management)
# ---------------------------------------------------------------------------
# Staff are ordinary Frappe Users scoped to the business via the same
# User Permission mechanism used everywhere else for tenant isolation —
# no custom "Staff" DocType. Role remains a business-facing label
# (Chef, Waiter, Cashier, etc.); authorization is enforced by the
# screen-permission guards below on every business-data endpoint.

def _default_screen_permissions(role):
    if role == ADMIN_ROLE:
        return sorted(ALL_SCREEN_PERMISSIONS)
    if role in ("Chef", "Baker"):
        return ["quick_sale", "kitchen"]
    if role == "Waiter":
        return ["quick_sale", "held_orders", "tables", "kitchen"]
    if role in ("Cashier", "Sales associate", "Receptionist"):
        return ["quick_sale", "held_orders", "order_history", "shift"]
    if role == "Stock keeper":
        return ["inventory", "reports"]
    if role in ("Pharmacist", "Technician"):
        return ["quick_sale", "held_orders", "order_history"]
    return ["quick_sale"]


def _is_company_owner(user, company=None):
    """Whether ``user`` is the recorded creator of their Company.

    Older FlexiPOS owners may predate the explicit Admin role field. The
    Company owner is the only safe legacy fallback; an arbitrary linked
    user with no role must never inherit Admin access.
    """
    if not user or user == "Guest":
        return False
    if not company:
        company = frappe.db.get_value(
            "User Permission", {"user": user, "allow": "Company"}, "for_value"
        )
    return (
        bool(company)
        and frappe.db.get_value("Company", company, "owner") == user
    )


def _effective_role(user):
    """Resolve a role without treating every missing value as Admin."""
    role = frappe.db.get_value("User", user, ROLE_FIELD)
    if role:
        return role
    return ADMIN_ROLE if _is_company_owner(user) else "Staff"


def _screen_permissions_for_user(user, role=None):
    role = role or _effective_role(user)
    if role == ADMIN_ROLE:
        return sorted(ALL_SCREEN_PERMISSIONS)
    raw = frappe.db.get_value("User", user, SCREEN_PERMISSIONS_FIELD)
    if raw:
        try:
            values = json.loads(raw)
            if isinstance(values, list):
                return [value for value in values if value in ALL_SCREEN_PERMISSIONS]
        except (TypeError, json.JSONDecodeError):
            pass
    return _default_screen_permissions(role)


def _require_screen_access(permission):
    _require_any_screen_access(permission)


def _require_any_screen_access(*permissions):
    """Require at least one server-side screen capability.

    Flutter route visibility is only presentation. Every whitelisted
    business-data method calls this guard so a hidden screen cannot be
    bypassed by invoking the HTTP API directly.
    """
    user = frappe.session.user
    if not user or user == "Guest":
        frappe.throw(_("Login required"), frappe.AuthenticationError)

    # Administrator is the site operator and must retain access to repair a
    # tenant's billing state. Tenant users are gated by their subscription
    # before screen capabilities are evaluated.
    if user != "Administrator":
        _require_subscription_access()

    requested = {
        value for value in permissions if value in ALL_SCREEN_PERMISSIONS
    }
    if not requested:
        frappe.throw(
            _("Invalid permission configuration"), frappe.PermissionError
        )

    granted = set(_screen_permissions_for_user(user))
    if requested.isdisjoint(granted):
        frappe.throw(
            _("You do not have permission to perform this action"),
            frappe.PermissionError,
        )


@frappe.whitelist()
def list_staff():
    """Every staff member linked to the caller's business, admin-only."""
    _ensure_custom_fields()
    company = _get_user_company()
    _require_screen_access("staff")
    _require_admin(company)

    user_names = frappe.get_all(
        "User Permission",
        filters={"allow": "Company", "for_value": company},
        pluck="user",
    )
    if not user_names:
        return {"staff": []}

    rows = frappe.get_all(
        "User",
        filters={"name": ("in", user_names)},
        fields=["name", "full_name", "email", ROLE_FIELD, DEVICE_ID_FIELD, SCREEN_PERMISSIONS_FIELD, "enabled", "last_active"],
        order_by="full_name",
    )
    return {
        "staff": [
            {
                "user": r.name,
                "full_name": r.full_name,
                "email": r.email,
                "role": _effective_role(r.name),
                "has_device": bool(r.get(DEVICE_ID_FIELD)),
                "enabled": r.enabled,
                "last_active": str(r.last_active) if r.last_active else None,
                "is_you": r.name == frappe.session.user,
                "screen_permissions": _screen_permissions_for_user(
                    r.name, _effective_role(r.name)
                ),
            }
            for r in rows
        ]
    }


@frappe.whitelist()
def add_staff(full_name, role, pin, email=None, screen_permissions=None):
    """Create a new staff account under the caller's business and bind
    a PIN for it immediately (the admin sets it on the staff member's
    behalf, e.g. handing them a freshly configured device)."""
    _ensure_custom_fields()
    company = _get_user_company()
    _require_screen_access("staff")
    _require_admin(company)

    full_name = (full_name or "").strip()
    role = (role or "").strip()
    pin = (pin or "").strip()
    if not full_name:
        frappe.throw(_("Name is required"))
    if not role:
        frappe.throw(_("Role is required"))
    if not pin.isdigit() or not 4 <= len(pin) <= 6:
        frappe.throw(_("PIN must be 4-6 digits"))

    email = (email or "").strip().lower()
    if not email:
        # Staff without email/password sign in via PIN only; Frappe
        # still needs a unique "email" identity, so synthesize one from
        # the company + name (never surfaced in the app's UI).
        slug = frappe.scrub(f"{company}-{full_name}")[:60]
        email = f"{slug}@staff.flexipos.local"
        candidate, counter = email, 1
        while frappe.db.exists("User", candidate):
            counter += 1
            candidate = f"{slug}{counter}@staff.flexipos.local"
        email = candidate
    elif frappe.db.exists("User", email):
        frappe.throw(_("An account with {0} already exists").format(email))

    if screen_permissions is not None:
        try:
            requested_permissions = json.loads(screen_permissions) if isinstance(screen_permissions, str) else screen_permissions
        except json.JSONDecodeError:
            frappe.throw(_("screen_permissions must be a valid list"))
        if not isinstance(requested_permissions, list):
            frappe.throw(_("screen_permissions must be a list"))
        initial_permissions = [value for value in requested_permissions if value in ALL_SCREEN_PERMISSIONS]
    else:
        initial_permissions = _default_screen_permissions(role)

    salt = secrets.token_hex(16)
    user = frappe.get_doc(
        {
            "doctype": "User",
            "email": email,
            "first_name": full_name,
            "user_type": "System User",
            "send_welcome_email": 0,
            ROLE_FIELD: role,
            PIN_HASH_FIELD: f"{salt}${_hash_pin(pin, salt)}",
            SCREEN_PERMISSIONS_FIELD: json.dumps(initial_permissions),
        }
    )
    user.flags.no_welcome_mail = True
    user.insert(ignore_permissions=True)

    for frappe_role in ("Sales User", "Accounts User", "Stock User"):
        if frappe.db.exists("Role", frappe_role):
            user.append("roles", {"role": frappe_role})
    user.flags.ignore_permissions = True
    user.save()

    frappe.get_doc(
        {
            "doctype": "User Permission",
            "user": user.name,
            "allow": "Company",
            "for_value": company,
        }
    ).insert(ignore_permissions=True)

    pos_profile = _assign_staff_to_company_pos_profile(user.name, company)

    return {
        "user": user.name,
        "full_name": user.full_name,
        "role": role,
        "pos_profile": pos_profile,
    }


def _assign_staff_to_company_pos_profile(user, company):
    """Add ``user`` to the current company's POS Profile users table.

    Prefer the profile used by the admin making this request, provided it
    belongs to the same company. Fall back to the company's first enabled
    profile. Never attach a user to a profile owned by another tenant and
    never create duplicate child rows.
    """
    profile_name = frappe.db.get_value(
        "POS Profile User",
        {
            "user": frappe.session.user,
            "parenttype": "POS Profile",
        },
        "parent",
    )
    if profile_name:
        owner = frappe.db.get_value("POS Profile", profile_name, "company")
        if owner != company:
            profile_name = None

    if not profile_name:
        profile_name = frappe.db.get_value(
            "POS Profile",
            {"company": company, "disabled": 0},
            "name",
            order_by="creation asc",
        )
    if not profile_name:
        frappe.throw(_("No enabled POS Profile found for company {0}").format(company))

    already_assigned = frappe.db.exists(
        "POS Profile User",
        {
            "parent": profile_name,
            "parenttype": "POS Profile",
            "user": user,
        },
    )
    if not already_assigned:
        profile = frappe.get_doc("POS Profile", profile_name)
        if profile.company != company or profile.disabled:
            frappe.throw(_("Invalid POS Profile for company {0}").format(company))
        profile.append("applicable_for_users", {"user": user, "default": 1})
        profile.flags.ignore_permissions = True
        profile.save()

    return profile_name


@frappe.whitelist()
def update_staff(user, full_name=None, email=None, role=None, new_pin=None, enabled=None, screen_permissions=None):
    """Admin edits an existing staff member: rename, change role, and/or
    reset their PIN (including the admin's own — device binding is left
    untouched so a PIN reset doesn't kick them off their current device
    unless they also re-register it)."""
    _ensure_custom_fields()
    company = _get_user_company()
    _require_screen_access("staff")
    _require_admin(company)
    _require_staff_of_company(user, company)

    email = (email or "").strip().lower()
    if email and email != user:
        if user == frappe.session.user:
            frappe.throw(_("You cannot change your own login email here"))
        if frappe.db.exists("User", email):
            frappe.throw(_("An account with {0} already exists").format(email))
        user = frappe.rename_doc("User", user, email, force=True)

    updates = {}
    if full_name and full_name.strip():
        updates["first_name"] = full_name.strip()
    if role and role.strip():
        updates[ROLE_FIELD] = role.strip()
    if new_pin is not None and new_pin != "":
        pin = new_pin.strip()
        if not pin.isdigit() or not 4 <= len(pin) <= 6:
            frappe.throw(_("PIN must be 4-6 digits"))
        salt = secrets.token_hex(16)
        updates[PIN_HASH_FIELD] = f"{salt}${_hash_pin(pin, salt)}"
    if enabled is not None:
        enabled = cint(enabled)
        if not enabled and user == frappe.session.user:
            frappe.throw(_("You cannot disable your own account"))
        updates["enabled"] = enabled
    if screen_permissions is not None:
        if user == frappe.session.user:
            frappe.throw(_("You cannot change your own screen permissions"))
        try:
            requested = json.loads(screen_permissions) if isinstance(screen_permissions, str) else screen_permissions
        except json.JSONDecodeError:
            frappe.throw(_("screen_permissions must be a valid list"))
        if not isinstance(requested, list):
            frappe.throw(_("screen_permissions must be a list"))
        cleaned = [value for value in requested if value in ALL_SCREEN_PERMISSIONS]
        updates[SCREEN_PERMISSIONS_FIELD] = json.dumps(cleaned)

    if updates:
        frappe.db.set_value("User", user, updates, update_modified=False)

    return {"user": user}


@frappe.whitelist()
def remove_staff(user):
    """Disable a staff member (never delete — past sales/audit trail
    reference them). Cannot disable yourself."""
    _ensure_custom_fields()
    company = _get_user_company()
    _require_screen_access("staff")
    _require_admin(company)
    _require_staff_of_company(user, company)
    if user == frappe.session.user:
        frappe.throw(_("You cannot remove your own account"))

    frappe.db.set_value("User", user, "enabled", 0, update_modified=False)
    return {"user": user, "enabled": False}


def _require_admin(company):
    """Only the business's Admin can manage staff. The very first user
    (the one who ran register_business) always has ADMIN_ROLE implicitly
    even if flexipos_role was never set, so onboarding doesn't lock
    itself out."""
    user = frappe.session.user
    role = _effective_role(user)
    if role != ADMIN_ROLE or not (
        frappe.db.get_value(
            "User Permission",
            {"user": user, "allow": "Company", "for_value": company},
            "name",
        )
        or _is_company_owner(user, company)
    ):
        frappe.throw(_("Only an Admin can manage staff"), frappe.PermissionError)


def _require_staff_of_company(user, company):
    belongs_to_company = frappe.db.exists(
        "User Permission",
        {
            "user": user,
            "allow": "Company",
            "for_value": company,
        },
    )
    if not frappe.db.exists("User", user) or not belongs_to_company:
        frappe.throw(
            _("Staff member is not available for this business"),
            frappe.PermissionError,
        )


# ---------------------------------------------------------------------------
# 5. OTP login (existing account on a new device)
# ---------------------------------------------------------------------------
# Accounts are password-less, so a new device authenticates with a
# one-time code. Delivery (SMTP / WhatsApp gateway) is not wired yet:
# the code is stored in the "FlexiPOS OTP" DocType, readable from the
# desk by an administrator who relays it manually. Once a gateway is
# configured, plug delivery into request_login_otp and switch the `otp`
# field to a hash.

@frappe.whitelist(allow_guest=True)
def request_login_otp(email, device_id):
    """Create a 6-digit login code for an existing account."""
    email = (email or "").strip().lower()
    device_id = (device_id or "").strip()
    validate_email_address(email, throw=True)
    if not device_id:
        frappe.throw(_("device_id is required"))

    _rate_limit(f"flexipos_otp_req:{email}", MAX_OTP_REQUESTS, 900)

    if not frappe.db.exists("User", {"name": email, "enabled": 1}):
        frappe.throw(_("No account found with {0}").format(email))

    # Only one live code per user.
    for name in frappe.get_all(
        OTP_DOCTYPE, filters={"user": email, "status": "Pending"}, pluck="name"
    ):
        frappe.db.set_value(OTP_DOCTYPE, name, "status", "Expired")

    otp = f"{secrets.randbelow(1_000_000):06d}"
    frappe.get_doc(
        {
            "doctype": OTP_DOCTYPE,
            "user": email,
            "otp": otp,
            "device_id": device_id,
            "status": "Pending",
            "expires_at": add_to_date(now_datetime(), seconds=OTP_TTL_SECONDS),
        }
    ).insert(ignore_permissions=True)

    # TODO: deliver via SMTP / WhatsApp gateway when configured.
    return {"requested": True, "expires_in_seconds": OTP_TTL_SECONDS}


@frappe.whitelist(allow_guest=True)
def verify_login_otp(email, otp, device_id, new_pin):
    """Verify the code, bind this device + PIN to the account, and
    return everything the app needs to finish onboarding."""
    email = (email or "").strip().lower()
    otp = (otp or "").strip()
    device_id = (device_id or "").strip()
    new_pin = (new_pin or "").strip()

    if not otp or not device_id:
        frappe.throw(_("Code and device_id are required"))
    if not new_pin.isdigit() or not 4 <= len(new_pin) <= 6:
        frappe.throw(_("PIN must be 4-6 digits"))

    attempts_key = f"flexipos_otp_verify:{email}"
    _rate_limit(attempts_key, MAX_OTP_ATTEMPTS, 600)

    row = frappe.get_all(
        OTP_DOCTYPE,
        filters={"user": email, "device_id": device_id, "status": "Pending"},
        fields=["name", "otp", "expires_at"],
        order_by="creation desc",
        limit=1,
    )
    if not row:
        frappe.throw(_("No code was requested for this device. Request one first."))
    record = row[0]

    if get_datetime(record.expires_at) < now_datetime():
        frappe.db.set_value(OTP_DOCTYPE, record.name, "status", "Expired")
        frappe.throw(_("This code has expired. Request a new one."))

    if not secrets.compare_digest(str(record.otp), otp):
        frappe.throw(_("Wrong code. Please try again."), frappe.AuthenticationError)

    frappe.db.set_value(OTP_DOCTYPE, record.name, "status", "Verified")
    frappe.cache().delete_value(attempts_key)

    # Bind this device + PIN (replaces any previous device binding).
    salt = secrets.token_hex(16)
    frappe.db.set_value(
        "User",
        email,
        {
            PIN_HASH_FIELD: f"{salt}${_hash_pin(new_pin, salt)}",
            DEVICE_ID_FIELD: device_id,
        },
        update_modified=False,
    )

    frappe.local.login_manager.login_as(email)
    business = get_my_business()
    credentials = _get_api_credentials(email)

    return {
        "user": email,
        "full_name": frappe.db.get_value("User", email, "full_name"),
        "sid": frappe.session.sid,
        **credentials,
        **business,
    }


def _rate_limit(cache_key, limit, window_seconds):
    count = cint(frappe.cache().get_value(cache_key))
    if count >= limit:
        frappe.throw(_("Too many attempts. Please try again later."))
    frappe.cache().set_value(cache_key, count + 1, expires_in_sec=window_seconds)
