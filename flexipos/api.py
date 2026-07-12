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
    Item.flexipos_variant_matrix (Clothing: size×colour stock matrix, JSON)
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
import json
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
KITCHEN_STATUSES = ["Placed", "Preparing", "Ready", "Served"]
PIN_HASH_FIELD = "flexipos_pin_hash"
DEVICE_ID_FIELD = "flexipos_device_id"
# Freeform (not a Select) since the sensible role set differs per business
# type (Chef/Waiter for a restaurant, Pharmacist/Cashier for a pharmacy,
# etc.) — see the Team & Roles screen's per-niche default suggestions.
ROLE_FIELD = "flexipos_role"
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
# Item tax % shown on receipts-to-be: stored per item and synced, but not
# yet folded into Sales Invoice taxes (needs a Sales Taxes and Charges
# row + client-side receipt math — its own project).
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

MAX_PIN_ATTEMPTS = 5
PIN_LOCKOUT_SECONDS = 300

OTP_DOCTYPE = "FlexiPOS OTP"
OTP_TTL_SECONDS = 600
MAX_OTP_REQUESTS = 3  # per email per 15 minutes
MAX_OTP_ATTEMPTS = 5  # wrong codes per email per 10 minutes


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


def _ensure_custom_fields():
    """Create the custom fields on first use if the site hasn't been
    migrated yet. Custom Field writes need admin rights, and the caller
    may be Guest (self-serve signup) — so elevate just for this step."""
    # Item.flexipos_reorder_point is the newest field; if it exists,
    # all the older ones do too (they are created together).
    if frappe.db.exists(
        "Custom Field", {"dt": "Item", "fieldname": MADE_TO_ORDER_FIELD}
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


@frappe.whitelist()
def setup_new_business(company_name, business_type=None, phone=None):
    """Create Company + default Branch + POS Profile for an already
    logged-in user. Returns the names of everything created."""
    company_name = (company_name or "").strip()
    if not company_name:
        frappe.throw(_("Business name is required"))
    if frappe.session.user == "Guest":
        frappe.throw(_("Login required"), frappe.AuthenticationError)
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

    profile_name = frappe.db.get_value("POS Profile User", {"user": user}, "parent")
    if not profile_name:
        company = frappe.db.get_value(
            "User Permission", {"user": user, "allow": "Company"}, "for_value"
        )
        if company:
            profile_name = frappe.db.get_value(
                "POS Profile", {"company": company, "disabled": 0}, "name"
            )
    if not profile_name:
        frappe.throw(_("No business is linked to this account yet"))

    profile = frappe.get_cached_doc("POS Profile", profile_name)
    business_type = frappe.db.get_value(
        "Company", profile.company, "flexipos_business_type"
    )
    role = frappe.db.get_value("User", user, ROLE_FIELD)
    return {
        "company": profile.company,
        "business_type": business_type,
        "role": role or ADMIN_ROLE,
        "pos_profile": profile.name,
        "customer": profile.customer,
        "currency": profile.currency,
        "warehouse": profile.warehouse,
        "price_list": profile.selling_price_list,
    }


def _setup_business(company_name, business_type, phone):
    """Shared setup core; caller owns commit/rollback."""
    company = _create_company(company_name, business_type, phone)
    branch = _create_branch(company)
    customer = _ensure_walk_in_customer()
    pos_profile = _create_pos_profile(company, customer)
    _link_current_user(company)
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
            "enable_perpetual_inventory": 0,
        }
    )
    company.insert(ignore_permissions=True)
    return company


def _create_branch(company):
    branch_name = f"{company.name} - Main"
    if frappe.db.exists("Branch", branch_name):
        return frappe.get_doc("Branch", branch_name)
    branch = frappe.get_doc({"doctype": "Branch", "branch": branch_name})
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
    _ensure_custom_fields()
    company = _get_user_company()
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
            "price_list": DEFAULT_PRICE_LIST,
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
    category_names = sorted({g.item_group for g in groups if g.item_group})
    categories = []
    if category_names:
        rows = frappe.get_all(
            "Item Group",
            filters={"name": ("in", category_names)},
            fields=["name", CATEGORY_IMAGE_FIELD],
        )
        categories = sorted(
            ({"name": r.name, "image": r.get(CATEGORY_IMAGE_FIELD)} for r in rows),
            key=lambda c: c["name"],
        )

    return {
        "server_time": server_time,
        "items": items,
        "prices": prices,
        "categories": categories,
        "modifier_groups": modifier_groups,
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
          "tax_rate": 5,               # item tax %, stored (not yet applied
                                       # to invoice totals)
          "stock_qty": 40,             # simple on-hand count, not ledger
          "dietary_flags": ["Halal"],  # Restaurant (list or CSV string)
          "recipe_depletion": 1,       # Restaurant: recipe/BOM flag
          "material": "100% Linen",    # Clothing
          "season": "SS26",            # Clothing
          "gender": "Unisex",          # Clothing: Men/Women/Unisex/Kids
          "variant_matrix": {...},     # Clothing size×colour stock matrix
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
    category = (data.get("category") or "").strip() or "Products"
    uom = (data.get("uom") or "Nos").strip()
    if not frappe.db.exists("UOM", uom):
        uom = "Nos"

    item_group = _ensure_item_group(category)
    item_code = (data.get("item_code") or "").strip()
    barcode = (data.get("barcode") or "").strip() or None

    if item_code:
        owner = frappe.db.get_value("Item", item_code, COMPANY_FIELD)
        if owner != company:
            frappe.throw(
                _("This product belongs to another business"),
                frappe.PermissionError,
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
            item.set(TAX_RATE_FIELD, flt(data.get("tax_rate")))
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
                TAX_RATE_FIELD: flt(data.get("tax_rate")),
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

    _set_selling_price(item.name, price)

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
    """Validate and normalise the clothing size×colour matrix into the
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
        owner = frappe.db.get_value("FlexiPOS Modifier Group", name, "flexipos_company")
        if owner is None:
            frappe.throw(_("Modifier group {0} does not exist").format(name))
        if owner != company:
            frappe.throw(
                _("Modifier group {0} belongs to another business").format(name),
                frappe.PermissionError,
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
            modifier = frappe.db.get_value(
                "FlexiPOS Modifier",
                modifier_id,
                ["flexipos_company", "modifier_name"],
                as_dict=True,
            )
            if not modifier:
                frappe.throw(_("Modifier {0} does not exist").format(modifier_id))
            if modifier.flexipos_company != company:
                frappe.throw(
                    _("Modifier {0} belongs to another business").format(modifier_id),
                    frappe.PermissionError,
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
        owner = frappe.db.get_value(
            "FlexiPOS Modifier Group", existing_name, "flexipos_company"
        )
        if owner != company:
            frappe.throw(
                _("This modifier group belongs to another business"),
                frappe.PermissionError,
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
    company = _get_user_company()
    owner = frappe.db.get_value("FlexiPOS Modifier Group", name, "flexipos_company")
    if owner is None:
        frappe.throw(_("Modifier group {0} does not exist").format(name))
    if owner != company:
        frappe.throw(
            _("This modifier group belongs to another business"),
            frappe.PermissionError,
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

    if target_type == "item":
        if frappe.db.get_value("Item", target_name, COMPANY_FIELD) != company:
            frappe.throw(
                _("This product belongs to another business"),
                frappe.PermissionError,
            )
        doctype, fieldname = "Item", "image"
    elif target_type == "category":
        if not frappe.db.exists("Item Group", target_name):
            frappe.throw(_("Category {0} does not exist").format(target_name))
        doctype, fieldname = "Item Group", CATEGORY_IMAGE_FIELD
    else:
        frappe.throw(_("target_type must be 'item' or 'category'"))

    file_doc = frappe.get_doc(
        {
            "doctype": "File",
            "file_name": filename,
            "attached_to_doctype": doctype,
            "attached_to_name": target_name,
            "attached_to_field": fieldname,
            "is_private": 0,
            "content": content_base64,
            "decode": True,
        }
    )
    file_doc.flags.ignore_permissions = True
    file_doc.insert(ignore_permissions=True)

    # Bumping `modified` lets delta sync carry the new image to other
    # devices of the same business.
    frappe.db.set_value(doctype, target_name, fieldname, file_doc.file_url)

    return {"image": file_doc.file_url}


def _get_user_company():
    """Resolve the single company the session user belongs to."""
    user = frappe.session.user
    if user == "Guest":
        frappe.throw(_("Login required"), frappe.AuthenticationError)
    company = frappe.db.get_value(
        "User Permission", {"user": user, "allow": "Company"}, "for_value"
    )
    if not company:
        profile = frappe.db.get_value("POS Profile User", {"user": user}, "parent")
        if profile:
            company = frappe.db.get_value("POS Profile", profile, "company")
    if not company:
        frappe.throw(_("No business is linked to this account yet"))
    return company


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


def _set_selling_price(item_code, rate):
    existing = frappe.db.get_value(
        "Item Price",
        {"item_code": item_code, "price_list": DEFAULT_PRICE_LIST, "selling": 1},
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
                "price_list": DEFAULT_PRICE_LIST,
                "selling": 1,
                "price_list_rate": rate,
            }
        ).insert(ignore_permissions=True)


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
            "Sales Invoice", {OFFLINE_ID_FIELD: offline_id}, "name"
        )
        if existing:
            results.append(
                {
                    "offline_invoice_id": offline_id,
                    "status": "duplicate",
                    "invoice": existing,
                }
            )
            continue

        savepoint = "flexipos_invoice"
        frappe.db.savepoint(savepoint)
        try:
            doc = _create_pos_invoice(payload, offline_id)
            results.append(
                {
                    "offline_invoice_id": offline_id,
                    "status": "success",
                    "invoice": doc.name,
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


def _create_pos_invoice(payload, offline_id):
    company = payload.get("company")
    if not company:
        frappe.throw(_("company is required"))

    pos_profile_name = payload.get("pos_profile") or frappe.db.get_value(
        "POS Profile", {"company": company, "disabled": 0}, "name"
    )
    if not pos_profile_name:
        frappe.throw(_("No POS Profile found for company {0}").format(company))
    profile = frappe.get_cached_doc("POS Profile", pos_profile_name)

    items = payload.get("items") or []
    if not items:
        frappe.throw(_("Invoice has no items"))

    posting = get_datetime(payload.get("posting_datetime") or now_datetime())
    order_type = payload.get("order_type")
    # Only Dine-in/Takeaway orders go through the kitchen; Delivery
    # (or no order type at all, e.g. non-restaurant businesses) skip it.
    kitchen_status = "Placed" if order_type in ("Dine-in", "Takeaway") else None

    doc = frappe.new_doc("Sales Invoice")
    doc.update(
        {
            "company": company,
            "customer": payload.get("customer") or profile.customer or WALK_IN_CUSTOMER,
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
        }
    )
    if payload.get("branch"):
        doc.branch = payload["branch"]

    for row in items:
        modifiers = row.get("modifiers") or []
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
                "item_code": row.get("item_code"),
                "qty": flt(row.get("qty")) or 1,
                "rate": flt(row.get("rate")),
                "uom": row.get("uom"),
                "warehouse": profile.warehouse,
                **({"description": description} if description else {}),
            },
        )

    doc.set_missing_values()

    payments = payload.get("payments") or []
    doc.set("payments", [])
    if payments:
        for p in payments:
            doc.append(
                "payments",
                {
                    "mode_of_payment": p.get("mode_of_payment") or "Cash",
                    "amount": flt(p.get("amount")),
                },
            )
    else:
        # Fall back to a full cash payment for the computed total.
        doc.run_method("calculate_taxes_and_totals")
        doc.append(
            "payments", {"mode_of_payment": "Cash", "amount": flt(doc.grand_total)}
        )

    doc.flags.ignore_permissions = True
    doc.insert()
    doc.submit()
    return doc


@frappe.whitelist()
def update_kitchen_status(invoice_name, status):
    """Advance an order's kitchen status from the Kitchen Display Screen.

    Best-effort from the client's point of view — kitchen status lives
    primarily in the device's local SQLite; this endpoint just mirrors
    it back to the Sales Invoice so other devices/reports can see it.
    """
    status = (status or "").strip()
    if status not in KITCHEN_STATUSES:
        frappe.throw(_("Invalid kitchen status"))

    company = _get_user_company()
    owner = frappe.db.get_value("Sales Invoice", invoice_name, "company")
    if not owner:
        frappe.throw(_("Order not found"))
    if owner != company:
        frappe.throw(_("This order belongs to another business"), frappe.PermissionError)

    frappe.db.set_value(
        "Sales Invoice", invoice_name, KITCHEN_STATUS_FIELD, status, update_modified=False
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
    items = items_json
    if isinstance(items, str):
        try:
            items = json.loads(items)
        except json.JSONDecodeError:
            frappe.throw(_("items_json is not valid JSON"))
    if not isinstance(items, list) or not items:
        frappe.throw(_("Select at least one item to refund"))

    company = _get_user_company()
    original = frappe.get_doc("Sales Invoice", invoice_name)
    if original.company != company:
        frappe.throw(_("This order belongs to another business"), frappe.PermissionError)
    if original.docstatus != 1:
        frappe.throw(_("Only submitted orders can be refunded"))
    if original.is_return:
        frappe.throw(_("This is already a credit note"))

    sold_qty = {row.item_code: flt(row.qty) for row in original.items}
    already_refunded = _refunded_qty_by_item(invoice_name)

    return_rows = []
    for row in items:
        if not isinstance(row, dict):
            continue
        item_code = (row.get("item_code") or "").strip()
        qty = flt(row.get("qty"))
        if not item_code or qty <= 0:
            continue
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


def _refunded_qty_by_item(invoice_name):
    """Sum of already-refunded quantities per item across every credit
    note issued against this invoice, so repeated partial refunds can't
    together exceed what was sold."""
    credit_notes = frappe.get_all(
        "Sales Invoice",
        filters={"return_against": invoice_name, "docstatus": 1, "is_return": 1},
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
    role = frappe.db.get_value("User", user.name, ROLE_FIELD)
    return {
        "user": user.name,
        "full_name": frappe.db.get_value("User", user.name, "full_name"),
        "role": role or ADMIN_ROLE,
        "sid": frappe.session.sid,
        **_get_api_credentials(user.name),
    }


def _hash_pin(pin, salt):
    return hashlib.pbkdf2_hmac("sha256", pin.encode(), salt.encode(), 60_000).hex()


# ---------------------------------------------------------------------------
# 4b. Team & roles (admin-only staff management)
# ---------------------------------------------------------------------------
# Staff are ordinary Frappe Users scoped to the business via the same
# User Permission mechanism used everywhere else for tenant isolation —
# no custom "Staff" DocType. Role is a freeform label (flexipos_role)
# rather than a Frappe Role, since it's just a display/grouping concept
# today (e.g. "Chef", "Waiter") and not yet wired to real permission
# scoping — see the memory note on this being a UI-first pass.

@frappe.whitelist()
def list_staff():
    """Every staff member linked to the caller's business, admin-only."""
    _ensure_custom_fields()
    company = _get_user_company()
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
        fields=["name", "full_name", "email", ROLE_FIELD, DEVICE_ID_FIELD, "enabled", "last_active"],
        order_by="full_name",
    )
    return {
        "staff": [
            {
                "user": r.name,
                "full_name": r.full_name,
                "email": r.email,
                "role": r.get(ROLE_FIELD) or ADMIN_ROLE,
                "has_device": bool(r.get(DEVICE_ID_FIELD)),
                "enabled": r.enabled,
                "last_active": str(r.last_active) if r.last_active else None,
                "is_you": r.name == frappe.session.user,
            }
            for r in rows
        ]
    }


@frappe.whitelist()
def add_staff(full_name, role, pin, email=None):
    """Create a new staff account under the caller's business and bind
    a PIN for it immediately (the admin sets it on the staff member's
    behalf, e.g. handing them a freshly configured device)."""
    _ensure_custom_fields()
    company = _get_user_company()
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
def update_staff(user, full_name=None, email=None, role=None, new_pin=None, enabled=None):
    """Admin edits an existing staff member: rename, change role, and/or
    reset their PIN (including the admin's own — device binding is left
    untouched so a PIN reset doesn't kick them off their current device
    unless they also re-register it)."""
    _ensure_custom_fields()
    company = _get_user_company()
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

    if updates:
        frappe.db.set_value("User", user, updates, update_modified=False)

    return {"user": user}


@frappe.whitelist()
def remove_staff(user):
    """Disable a staff member (never delete — past sales/audit trail
    reference them). Cannot disable yourself."""
    company = _get_user_company()
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
    role = frappe.db.get_value("User", frappe.session.user, ROLE_FIELD)
    if role and role != ADMIN_ROLE:
        frappe.throw(_("Only an Admin can manage staff"), frappe.PermissionError)


def _require_staff_of_company(user, company):
    owner = frappe.db.get_value(
        "User Permission", {"user": user, "allow": "Company"}, "for_value"
    )
    if owner != company:
        frappe.throw(_("This staff member belongs to another business"), frappe.PermissionError)


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
