"""
Rate Limit Plugin — Prevents abuse by limiting requests per user in a time window.

Why needed: Catches brute-force attacks and DoS attempts that other layers miss.
Input guardrails check content, not frequency — rate limiter fills that gap.
"""
from collections import defaultdict, deque
import time

from google.genai import types
from google.adk.plugins import base_plugin
from google.adk.agents.invocation_context import InvocationContext


class RateLimitPlugin(base_plugin.BasePlugin):
    """Blocks users who exceed max requests in a sliding time window."""

    def __init__(self, max_requests=10, window_seconds=60):
        super().__init__(name="rate_limiter")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.user_windows = defaultdict(deque)
        self.blocked_count = 0

    def _block_response(self, message: str) -> types.Content:
        return types.Content(
            role="model",
            parts=[types.Part.from_text(text=message)],
        )

    async def on_user_message_callback(
        self,
        *,
        invocation_context: InvocationContext,
        user_message: types.Content,
    ) -> types.Content | None:
        user_id = invocation_context.user_id if invocation_context else "anonymous"
        now = time.time()
        window = self.user_windows[user_id]

        while window and window[0] < now - self.window_seconds:
            window.popleft()

        if len(window) >= self.max_requests:
            self.blocked_count += 1
            wait = int(self.window_seconds - (now - window[0]))
            return self._block_response(
                f"Rate limit exceeded. Please wait {wait} seconds before sending another request."
            )

        window.append(now)
        return None
