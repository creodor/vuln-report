import unittest

from vuln_report.llm import OpenRouterError, _extract_message_content, _strip_code_fences


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


if __name__ == "__main__":
    unittest.main()

