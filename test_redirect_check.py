import unittest

from redirect_check import (
    points_to_canary,
    redirect_parameters,
    replace_parameter,
    validate_http_url,
)


class RedirectCheckTests(unittest.TestCase):
    def test_redirect_parameters_are_unique_and_keep_order(self):
        url = "https://app.example/path?a=1&next=%2Fhome&a=2"
        self.assertEqual(redirect_parameters(url), ["a", "next"])

    def test_replace_parameter_preserves_other_query_values(self):
        url = "https://app.example/path?next=%2Fhome&lang=en#section"
        result = replace_parameter(url, "next", "https://redirect-check.invalid/")
        self.assertEqual(
            result,
            "https://app.example/path?next=https%3A%2F%2Fredirect-check.invalid%2F&lang=en#section",
        )

    def test_canary_comparison_requires_exact_hostname(self):
        canary = "https://redirect-check.invalid/"
        self.assertTrue(
            points_to_canary(
                "https://redirect-check.invalid/out",
                "https://app.example/",
                canary,
            )
        )
        self.assertFalse(
            points_to_canary(
                "https://redirect-check.invalid.attacker.example/",
                "https://app.example/",
                canary,
            )
        )

    def test_relative_location_does_not_match_external_canary(self):
        self.assertFalse(
            points_to_canary(
                "/account",
                "https://app.example/login",
                "https://redirect-check.invalid/",
            )
        )

    def test_url_validation_rejects_non_http_and_credentials(self):
        for value in ("ftp://app.example/path", "https://user:pass@app.example/"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_http_url(value, "target")


if __name__ == "__main__":
    unittest.main()
