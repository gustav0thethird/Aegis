"""
Unit tests for _check_ip and _check_hours in api.py.
No database or network required.
"""

from datetime import datetime, time, timezone
from unittest.mock import patch

from aegis.api import _check_ip, _check_hours


class TestCheckIp:
    def test_no_allowlist_permits_all(self):
        assert _check_ip("1.2.3.4", None) is True
        assert _check_ip("1.2.3.4", []) is True

    def test_unknown_source_ip_fails_open(self):
        # source IP unavailable (behind proxy etc.) — fail open rather than block
        assert _check_ip(None, ["10.0.0.0/8"]) is True

    def test_exact_host_match(self):
        assert _check_ip("10.0.0.1", ["10.0.0.1/32"]) is True

    def test_cidr_match(self):
        assert _check_ip("10.0.1.50", ["10.0.1.0/24"]) is True

    def test_first_cidr_in_list_matches(self):
        assert _check_ip("192.168.1.5", ["10.0.0.0/8", "192.168.0.0/16"]) is True

    def test_second_cidr_in_list_matches(self):
        assert _check_ip("10.5.5.5", ["192.168.0.0/16", "10.0.0.0/8"]) is True

    def test_no_cidr_matches(self):
        assert _check_ip("8.8.8.8", ["10.0.0.0/8", "192.168.0.0/16"]) is False

    def test_invalid_cidr_returns_false(self):
        assert _check_ip("1.2.3.4", ["not_a_valid_cidr"]) is False


class TestCheckHours:
    def _mock_now(self, hour: int, minute: int = 0):
        return datetime(2026, 3, 16, hour, minute, tzinfo=timezone.utc)

    def test_no_restriction_always_allowed(self):
        assert _check_hours(None, None) is True
        assert _check_hours(time(9, 0), None) is True
        assert _check_hours(None, time(18, 0)) is True

    def test_within_window(self):
        with patch("api.datetime") as mock_dt:
            mock_dt.now.return_value = self._mock_now(14)
            assert _check_hours(time(9, 0), time(18, 0)) is True

    def test_outside_window(self):
        with patch("api.datetime") as mock_dt:
            mock_dt.now.return_value = self._mock_now(20)
            assert _check_hours(time(9, 0), time(18, 0)) is False

    def test_at_window_start_boundary(self):
        with patch("api.datetime") as mock_dt:
            mock_dt.now.return_value = self._mock_now(9)
            assert _check_hours(time(9, 0), time(18, 0)) is True

    def test_at_window_end_boundary(self):
        with patch("api.datetime") as mock_dt:
            mock_dt.now.return_value = self._mock_now(18)
            assert _check_hours(time(9, 0), time(18, 0)) is True

    def test_overnight_window_within_before_midnight(self):
        # 22:00-06:00, now 23:30 → allowed
        with patch("api.datetime") as mock_dt:
            mock_dt.now.return_value = self._mock_now(23, 30)
            assert _check_hours(time(22, 0), time(6, 0)) is True

    def test_overnight_window_within_after_midnight(self):
        # 22:00-06:00, now 03:00 → allowed
        with patch("api.datetime") as mock_dt:
            mock_dt.now.return_value = self._mock_now(3)
            assert _check_hours(time(22, 0), time(6, 0)) is True

    def test_overnight_window_outside(self):
        # 22:00-06:00, now 12:00 → denied
        with patch("api.datetime") as mock_dt:
            mock_dt.now.return_value = self._mock_now(12)
            assert _check_hours(time(22, 0), time(6, 0)) is False
