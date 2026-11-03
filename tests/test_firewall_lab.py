"""Tests for firewall-lab. Run: python3 -m unittest discover -s tests -v"""

import unittest

from firewall_lab import (Packet, Rule, evaluate, format_verdict, parse_rules,
                          parse_traffic, simulate)


def rules_and_defaults(text):
    return parse_rules(text)


class TestAllowMatch(unittest.TestCase):
    def test_allow_match(self):
        rules, defaults = rules_and_defaults("allow in tcp 22 from any\n")
        v = evaluate(Packet("203.0.113.5", 22, "tcp", "in"), rules, defaults)
        self.assertEqual(v.outcome, "allow")
        self.assertFalse(v.defaulted)
        self.assertIsNotNone(v.matched_rule)

    def test_first_match_wins(self):
        rules, defaults = rules_and_defaults(
            "deny in tcp 22 from any\nallow in tcp 22 from any\n")
        v = evaluate(Packet("203.0.113.5", 22, "tcp", "in"), rules, defaults)
        self.assertEqual(v.outcome, "deny")

    def test_wrong_direction_or_protocol_does_not_match(self):
        rules, defaults = rules_and_defaults("allow in tcp 22 from any\n")
        v = evaluate(Packet("203.0.113.5", 22, "tcp", "out"), rules, defaults)
        self.assertTrue(v.defaulted)
        v = evaluate(Packet("203.0.113.5", 22, "udp", "in"), rules, defaults)
        self.assertTrue(v.defaulted)


class TestDenyMatch(unittest.TestCase):
    def test_deny_match(self):
        rules, defaults = rules_and_defaults("deny in tcp 23 from any\n")
        v = evaluate(Packet("203.0.113.5", 23, "tcp", "in"), rules, defaults)
        self.assertEqual(v.outcome, "deny")
        self.assertFalse(v.defaulted)


class TestDefaultPolicy(unittest.TestCase):
    def test_default_deny_in(self):
        rules, defaults = rules_and_defaults(
            "default-policy in deny\ndefault-policy out allow\n")
        v = evaluate(Packet("203.0.113.5", 3389, "tcp", "in"), rules, defaults)
        self.assertEqual(v.outcome, "deny")
        self.assertTrue(v.defaulted)
        self.assertIsNone(v.matched_rule)

    def test_default_allow_out(self):
        rules, defaults = rules_and_defaults(
            "default-policy in deny\ndefault-policy out allow\n")
        v = evaluate(Packet("203.0.113.5", 443, "tcp", "out"), rules, defaults)
        self.assertEqual(v.outcome, "allow")
        self.assertTrue(v.defaulted)

    def test_builtin_defaults_without_policy_lines(self):
        rules, defaults = rules_and_defaults("allow in tcp 22 from any\n")
        self.assertEqual(defaults["in"], "deny")
        self.assertEqual(defaults["out"], "allow")


class TestPortRanges(unittest.TestCase):
    def test_inside_range_matches(self):
        rules, defaults = rules_and_defaults(
            "allow in tcp 8000-8100 from any\n")
        self.assertEqual(
            evaluate(Packet("1.2.3.4", 8050, "tcp", "in"),
                     rules, defaults).outcome, "allow")

    def test_range_boundaries_match(self):
        rules, defaults = rules_and_defaults(
            "allow in tcp 8000-8100 from any\n")
        for port in (8000, 8100):
            self.assertEqual(
                evaluate(Packet("1.2.3.4", port, "tcp", "in"),
                         rules, defaults).outcome, "allow")

    def test_outside_range_falls_to_default(self):
        rules, defaults = rules_and_defaults(
            "allow in tcp 8000-8100 from any\n")
        v = evaluate(Packet("1.2.3.4", 9000, "tcp", "in"), rules, defaults)
        self.assertEqual(v.outcome, "deny")
        self.assertTrue(v.defaulted)


class TestCidrMatching(unittest.TestCase):
    def test_inside_cidr_matches(self):
        rules, defaults = rules_and_defaults(
            "allow in tcp 443 from 192.168.1.0/24\n")
        v = evaluate(Packet("192.168.1.50", 443, "tcp", "in"),
                     rules, defaults)
        self.assertEqual(v.outcome, "allow")

    def test_outside_cidr_does_not_match(self):
        rules, defaults = rules_and_defaults(
            "allow in tcp 443 from 192.168.1.0/24\n")
        v = evaluate(Packet("192.168.2.50", 443, "tcp", "in"),
                     rules, defaults)
        self.assertTrue(v.defaulted)

    def test_single_host_cidr(self):
        rules, defaults = rules_and_defaults(
            "deny in tcp any from 10.0.0.0/8\n")
        v = evaluate(Packet("10.0.0.9", 443, "tcp", "in"), rules, defaults)
        self.assertEqual(v.outcome, "deny")
        v = evaluate(Packet("172.16.0.9", 443, "tcp", "in"), rules, defaults)
        self.assertTrue(v.defaulted)


class TestParsingAndUfw(unittest.TestCase):
    def test_parse_sample_files_round_trip(self):
        with open("examples/rules.txt", encoding="utf-8") as fh:
            rules, defaults = parse_rules(fh.read())
        with open("examples/traffic.txt", encoding="utf-8") as fh:
            packets = parse_traffic(fh.read())
        self.assertEqual(len(rules), 7)
        self.assertEqual(len(packets), 10)
        results = simulate(packets, rules, defaults)
        outcomes = [v.outcome for v in results]
        # 22 allow, 23 deny, 80 allow, 8050-in-LAN allow, 9000 default deny,
        # 10.x 443 ALLOW (the allow-443 rule comes before the deny-10/8
        # rule, so first-match wins -- rule order matters), 10.x 22 allow
        # (SSH rule is first), 3389 default deny, 53 udp out allow x2
        self.assertEqual(outcomes, ["allow", "deny", "allow", "allow", "deny",
                                    "allow", "allow", "deny", "allow", "allow"])

    def test_ufw_rendering(self):
        rule = Rule("allow", "in", "tcp", 8000, 8100, "192.168.1.0/24")
        self.assertEqual(rule.to_ufw(),
                         "ufw allow in from 192.168.1.0/24 proto tcp "
                         "to any port 8000:8100")
        self.assertEqual(Rule("deny", "in", "tcp", 23, 23, "any").to_ufw(),
                         "ufw deny in from any proto tcp to any port 23")

    def test_bad_rule_raises(self):
        with self.assertRaises(ValueError):
            parse_rules("permit in tcp 22 from any\n")

    def test_format_verdict_mentions_rule_or_default(self):
        rules, defaults = rules_and_defaults("allow in tcp 22 from any\n")
        v = evaluate(Packet("1.2.3.4", 22, "tcp", "in"), rules, defaults)
        self.assertIn("ALLOW", format_verdict(v))
        v2 = evaluate(Packet("1.2.3.4", 9999, "tcp", "in"), rules, defaults)
        self.assertIn("default policy", format_verdict(v2))


if __name__ == "__main__":
    unittest.main()
