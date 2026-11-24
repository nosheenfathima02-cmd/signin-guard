import unittest

from signin_guard.detections import run_all, brute_force, password_spray, impossible_travel, mfa_fatigue
from signin_guard.generate_sample import generate


class DetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.logs = generate()

    def test_brute_force_with_success_is_high(self):
        [a] = brute_force(self.logs)
        self.assertEqual(a.user, "chen.li@contoso.ca")
        self.assertEqual(a.severity, "high")
        self.assertIn("T1078", a.mitre)

    def test_password_spray(self):
        [a] = password_spray(self.logs)
        self.assertEqual(a.ip, "45.153.160.2")

    def test_impossible_travel(self):
        users = [a.user for a in impossible_travel(self.logs)]
        self.assertIn("diana.roy@contoso.ca", users)
        self.assertEqual(len(users), len(set(users)), "one alert per trip, not per leg")

    def test_mfa_fatigue_with_approval_is_critical(self):
        [a] = mfa_fatigue(self.logs)
        self.assertEqual(a.severity, "critical")

    def test_normal_traffic_has_no_false_positives(self):
        attack_users = {"chen.li@contoso.ca", "diana.roy@contoso.ca", "omar.haddad@contoso.ca", "10 accounts"}
        self.assertTrue({a.user for a in run_all(self.logs)} <= attack_users)


if __name__ == "__main__":
    unittest.main()
