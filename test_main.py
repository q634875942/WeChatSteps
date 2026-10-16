import contextlib
import io
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qs

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

import main


class LoginTests(unittest.TestCase):
    def check_login(self, user, expected_user, third_name):
        requests_seen = []

        def post(url, *, data, headers, **kwargs):
            requests_seen.append(url)
            if len(requests_seen) == 1:
                self.assertEqual(
                    url, "https://api-user.zepp.com/v2/registrations/tokens"
                )
                self.assertEqual(headers["x-hm-ekv"], "1")
                self.assertFalse(kwargs["allow_redirects"])
                cipher = AES.new(
                    b"xeNtBVqzDc6tuNTh", AES.MODE_CBC, b"MAAAYAAAAAAAAABg"
                )
                form = parse_qs(unpad(cipher.decrypt(data), AES.block_size).decode())
                self.assertEqual(form["emailOrPhone"], [expected_user])
                self.assertEqual(form["password"], ["p'a ss&word"])
                return SimpleNamespace(
                    status_code=303,
                    headers={"Location": "https://example.com/callback?access=test-code"},
                )
            self.assertEqual(url, "https://account.huami.com/v2/client/login")
            self.assertNotIn("x-hm-ekv", headers)
            self.assertEqual(data["code"], "test-code")
            self.assertEqual(data["third_name"], third_name)
            return SimpleNamespace(
                json=lambda: {
                    "result": "ok",
                    "token_info": {"login_token": "test-token", "user_id": "123"},
                }
            )

        with patch("main.requests.post", side_effect=post):
            self.assertEqual(main.login(user, "p'a ss&word"), ("test-token", "123"))
        self.assertEqual(len(requests_seen), 2)

    def test_email_login_uses_encrypted_request_and_email_grant(self):
        self.check_login("demo@example.com", "demo@example.com", "email")

    def test_phone_login_adds_country_prefix(self):
        self.check_login("13800138000", "+8613800138000", "huami_phone")

    def test_rejected_login_does_not_request_client_token(self):
        response = SimpleNamespace(
            status_code=303,
            headers={"Location": "https://example.com/callback?error=401"},
        )
        with patch("main.requests.post", return_value=response) as post:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main.login("demo@example.com", "wrong"), (0, 0))
        self.assertEqual(post.call_count, 1)

    def test_login_failure_exits_unsuccessfully(self):
        with patch("main.login", return_value=(0, 0)):
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    main.main("demo@example.com", "wrong", "12000")
        self.assertEqual(error.exception.code, 1)

    def test_timestamp_uses_local_clock_without_network(self):
        with patch("main.time.time", return_value=1700000000.125):
            with patch("main.requests.get", side_effect=AssertionError("network call")):
                self.assertEqual(main.get_time(), "1700000000125")


if __name__ == "__main__":
    unittest.main()
