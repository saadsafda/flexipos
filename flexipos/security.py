import frappe


def add_security_headers(response=None, request=None):
    """Harden API/web responses without changing offline client behavior."""
    headers = frappe.local.response_headers
    headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    headers.set("X-Content-Type-Options", "nosniff")
    headers.set("Referrer-Policy", "strict-origin-when-cross-origin")
    headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return response
