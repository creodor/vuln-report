import unittest

from vuln_report.llm import (
    OpenRouterError,
    _extract_message_content,
    _format_openrouter_http_error,
    _parse_openrouter_response_body,
    _strip_code_fences,
)


class LlmParsingTests(unittest.TestCase):
    def test_strip_code_fences_removes_json_fence(self):
        content = '```json\n{"summary": "ok"}\n```'

        self.assertEqual(_strip_code_fences(content), '{"summary": "ok"}')

    def test_extract_message_content_rejects_null_content(self):
        with self.assertRaises(OpenRouterError):
            _extract_message_content({"content": None}, {"finish_reason": "stop"})

    def test_extract_message_content_accepts_text_blocks(self):
        message = {"content": [{"type": "text", "text": '{"summary": "ok"}'}]}

        self.assertEqual(
            _extract_message_content(message, {"finish_reason": "stop"}),
            '{"summary": "ok"}',
        )

    def test_extract_message_content_surfaces_provider_error(self):
        with self.assertRaisesRegex(OpenRouterError, "throttled"):
            _extract_message_content(
                {"content": None, "error": {"message": "model is throttled"}},
                {"finish_reason": "stop"},
            )

    def test_http_error_formatter_identifies_rate_limit(self):
        message = _format_openrouter_http_error(
            429,
            '{"error": {"message": "free model rate limit exceeded"}}',
        )

        self.assertIn("quota-limited or throttled", message)

    def test_parse_response_body_rejects_invalid_json(self):
        with self.assertRaisesRegex(OpenRouterError, "non-JSON or truncated"):
            _parse_openrouter_response_body('{"choices": [')


if __name__ == "__main__":
    unittest.main()
