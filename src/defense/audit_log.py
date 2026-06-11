"""
Audit Log Plugin — Records every interaction for compliance and analysis.

Why needed: Without audit logs, you can't detect attack patterns, measure guardrail
effectiveness, or satisfy compliance requirements (PCI-DSS, SOX). Catches nothing
directly but enables all other monitoring to work.
"""
import json
import time
from datetime import datetime

from google.genai import types
from google.adk.plugins import base_plugin


class AuditLogPlugin(base_plugin.BasePlugin):
    """Records every user interaction, guardrail decision, and latency."""

    def __init__(self):
        super().__init__(name="audit_log")
        self.logs = []

    def _extract_text(self, content) -> str:
        text = ""
        if content and hasattr(content, "parts") and content.parts:
            for part in content.parts:
                if hasattr(part, "text") and part.text:
                    text += part.text
        return text

    async def on_user_message_callback(
        self, *, invocation_context, user_message
    ) -> None:
        entry = {
            "timestamp": datetime.now().isoformat(),
            "user_id": invocation_context.user_id if invocation_context else "anonymous",
            "session_id": invocation_context.session.id if invocation_context and hasattr(invocation_context, "session") and invocation_context.session else "unknown",
            "input": self._extract_text(user_message),
            "phase": "input",
            "blocked": False,
        }
        self.logs.append(entry)
        return None

    async def after_model_callback(self, *, callback_context, llm_response):
        if self.logs:
            entry = self.logs[-1]
            entry["output"] = self._extract_text(llm_response.content) if hasattr(llm_response, "content") else ""
            entry["latency_ms"] = int((time.time() - datetime.fromisoformat(entry["timestamp"]).timestamp()) * 1000)
            entry["phase"] = "complete"
        return llm_response

    def export_json(self, filepath="audit_log.json"):
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.logs, f, indent=2, default=str)
        print(f"Audit log exported to {filepath} ({len(self.logs)} entries)")

    def get_stats(self) -> dict:
        total = len(self.logs)
        blocked = sum(1 for e in self.logs if e.get("blocked"))
        return {
            "total_requests": total,
            "blocked_requests": blocked,
            "block_rate": blocked / total if total > 0 else 0,
        }
