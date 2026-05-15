"""Tests for S1-T3: Network collector (best-effort)."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
from collections import namedtuple

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scanner.collector.network_collector import (
    _connection_to_dict,
    collect_network_connections,
)

Addr = namedtuple("Addr", ["ip", "port"])


def _make_conn(
    pid: int, laddr: tuple | None, raddr: tuple | None, status: str = "ESTABLISHED",
) -> MagicMock:
    conn = MagicMock()
    conn.pid = pid
    conn.laddr = Addr(*laddr) if laddr else None
    conn.raddr = Addr(*raddr) if raddr else None
    conn.status = status
    conn.type = 1
    conn.family = 2
    return conn


class ConnectionToDictTests(unittest.TestCase):
    def test_outbound_connection(self) -> None:
        conn = _make_conn(10, ("127.0.0.1", 5000), ("93.184.216.34", 443))
        result = _connection_to_dict(conn, 10)
        self.assertIsNotNone(result)
        self.assertEqual(result["remote_ip"], "93.184.216.34")
        self.assertEqual(result["remote_port"], 443)
        self.assertEqual(result["pid"], 10)

    def test_listening_socket_skipped(self) -> None:
        conn = _make_conn(10, ("0.0.0.0", 80), None, status="LISTEN")
        result = _connection_to_dict(conn, 10)
        self.assertIsNone(result)

    def test_no_remote_address_skipped(self) -> None:
        conn = MagicMock()
        conn.raddr = None
        result = _connection_to_dict(conn, 10)
        self.assertIsNone(result)


class CollectNetworkConnectionsTests(unittest.TestCase):
    @patch("scanner.collector.network_collector.psutil.Process")
    @patch("scanner.collector.network_collector.psutil.net_connections")
    def test_captures_outbound(self, mock_net: MagicMock, mock_proc_cls: MagicMock) -> None:
        mock_net.return_value = [
            _make_conn(42, ("10.0.0.1", 12345), ("8.8.8.8", 53)),
        ]
        mock_proc = MagicMock()
        mock_proc.exe.return_value = r"C:\dns_client.exe"
        mock_proc_cls.return_value = mock_proc

        events = collect_network_connections(host_id="h1")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, "net_conn")
        self.assertEqual(events[0].payload["remote_ip"], "8.8.8.8")
        self.assertEqual(events[0].payload["image_path"], r"C:\dns_client.exe")
        self.assertEqual(events[0].payload["signer_publisher"], "unknown")
        self.assertIn("identity_key", events[0].payload)

    @patch("scanner.collector.network_collector.psutil.net_connections")
    def test_graceful_on_access_denied(self, mock_net: MagicMock) -> None:
        import psutil
        mock_net.side_effect = psutil.AccessDenied(pid=0)
        events = collect_network_connections(host_id="h1")
        self.assertEqual(len(events), 0)

    @patch("scanner.collector.network_collector.psutil.Process")
    @patch("scanner.collector.network_collector.psutil.net_connections")
    def test_skips_no_pid(self, mock_net: MagicMock, mock_proc_cls: MagicMock) -> None:
        conn = _make_conn(0, ("10.0.0.1", 100), ("1.2.3.4", 80))
        conn.pid = None
        mock_net.return_value = [conn]
        events = collect_network_connections(host_id="h1")
        self.assertEqual(len(events), 0)

    @patch("scanner.collector.network_collector.psutil.Process")
    @patch("scanner.collector.network_collector.psutil.net_connections")
    def test_exe_resolution_cached(self, mock_net: MagicMock, mock_proc_cls: MagicMock) -> None:
        mock_net.return_value = [
            _make_conn(42, ("10.0.0.1", 100), ("1.2.3.4", 80)),
            _make_conn(42, ("10.0.0.1", 101), ("5.6.7.8", 443)),
        ]
        mock_proc = MagicMock()
        mock_proc.exe.return_value = r"C:\browser.exe"
        mock_proc_cls.return_value = mock_proc

        events = collect_network_connections(host_id="h1")
        self.assertEqual(len(events), 2)
        # Process constructor should be called only once per PID
        mock_proc_cls.assert_called_once_with(42)


if __name__ == "__main__":
    unittest.main()
