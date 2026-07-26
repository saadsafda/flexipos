import frappe
from frappe import _
from frappe.model.document import Document


class FlexiPOSKnowledgeArticle(Document):
    def validate(self):
        self.article_key = (self.article_key or "").strip().lower()[:140]
        self.title = (self.title or "").strip()[:140]
        self.summary = (self.summary or "").strip()[:500]
        self.body = (self.body or "").strip()[:10000]
        if not self.article_key or not self.title or not self.body:
            frappe.throw(_("Article key, title and body are required"))

