from __future__ import annotations

from unittest.mock import MagicMock, patch

from cemi.collectors.network_connections import NetworkConnectionsCollector
from cemi.models import CollectorHealth


class TestNetworkConnectionsCollector:
    def test_psutil_unavailable_skips(self) -> None:
        with patch("cemi.collectors.network_connections._PSUTIL_AVAILABLE", False):
            collector = NetworkConnectionsCollector()
            items, health = collector.collect()
            assert items == []
            assert health.ran_successfully is False
            assert "psutil library not available" in health.skipped_reason

    @patch("cemi.collectors.network_connections.psutil")
    def test_returns_list_and_health(self, mock_psutil: MagicMock) -> None:
        mock_conn = MagicMock()
        mock_conn.pid = 1234
        mock_conn.laddr.ip = "127.0.0.1"
        mock_conn.laddr.port = 54321
        mock_conn.raddr.ip = "8.8.8.8"
        mock_conn.raddr.port = 443
        mock_conn.status = "ESTABLISHED"

        mock_proc = MagicMock()
        mock_proc.name.return_value = "test.exe"
        mock_proc.exe.return_value = r"C:\Program Files\test\test.exe"

        mock_psutil.net_connections.return_value = [mock_conn]
        mock_psutil.Process.return_value = mock_proc

        collector = NetworkConnectionsCollector()
        items, health = collector.collect()

        assert len(items) == 1
        conn = items[0]
        assert conn["pid"] == 1234
        assert conn["remote_address"] == "8.8.8.8"
        assert conn["remote_port"] == 443
        assert "local_address" not in conn
        assert conn["local_port"] == 54321
        assert conn["process_name"] == "test.exe"
        assert conn["exe_path_redacted"] is not None

        assert health.ran_successfully is True
        assert health.items_collected == 1

    @patch("cemi.collectors.network_connections.psutil")
    def test_handles_empty_connections(self, mock_psutil: MagicMock) -> None:
        mock_psutil.net_connections.return_value = []

        collector = NetworkConnectionsCollector()
        items, health = collector.collect()

        assert items == []
        assert health.items_collected == 0

    @patch("cemi.collectors.network_connections.psutil")
    def test_handles_access_denied(self, mock_psutil: MagicMock) -> None:
        mock_conn = MagicMock()
        mock_conn.pid = 5678
        mock_conn.laddr.ip = "127.0.0.1"
        mock_conn.laddr.port = 54321
        mock_conn.raddr.ip = "1.2.3.4"
        mock_conn.raddr.port = 80
        mock_conn.status = "ESTABLISHED"

        mock_psutil.net_connections.return_value = [mock_conn]
        mock_psutil.Process.side_effect = Exception("Access denied")

        collector = NetworkConnectionsCollector()
        items, health = collector.collect()

        # Connection should still be collected even if process details fail
        assert len(items) == 1  # Connection metadata collected
        assert health.privilege_level == "partial"

    @patch("cemi.collectors.network_connections.psutil")
    def test_redacts_exe_path(self, mock_psutil: MagicMock) -> None:
        mock_conn = MagicMock()
        mock_conn.pid = 1234
        mock_conn.laddr.ip = "127.0.0.1"
        mock_conn.laddr.port = 54321
        mock_conn.raddr.ip = "8.8.8.8"
        mock_conn.raddr.port = 443
        mock_conn.status = "ESTABLISHED"

        mock_proc = MagicMock()
        mock_proc.name.return_value = "chrome.exe"
        mock_proc.exe.return_value = r"C:\Users\alice\AppData\Local\Google\Chrome\chrome.exe"

        mock_psutil.net_connections.return_value = [mock_conn]
        mock_psutil.Process.return_value = mock_proc

        collector = NetworkConnectionsCollector()
        items, health = collector.collect()

        conn = items[0]
        assert "alice" not in conn["exe_path_redacted"]
        assert "exe_path" not in conn

    @patch("cemi.collectors.network_connections.psutil")
    def test_exe_path_not_in_connection_dict(self, mock_psutil: MagicMock) -> None:
        mock_conn = MagicMock()
        mock_conn.pid = 1234
        mock_conn.laddr.ip = "127.0.0.1"
        mock_conn.laddr.port = 54321
        mock_conn.raddr.ip = "8.8.8.8"
        mock_conn.raddr.port = 443
        mock_conn.status = "ESTABLISHED"

        mock_proc = MagicMock()
        mock_proc.name.return_value = "test.exe"
        mock_proc.exe.return_value = r"C:\Users\alice\AppData\test.exe"

        mock_psutil.net_connections.return_value = [mock_conn]
        mock_psutil.Process.return_value = mock_proc

        collector = NetworkConnectionsCollector()
        items, health = collector.collect()

        conn = items[0]
        assert "exe_path" not in conn
        assert "exe_path_redacted" in conn
        assert conn["exe_path_redacted"] is not None

    @patch("cemi.collectors.network_connections.psutil")
    def test_local_address_not_in_connection_dict(self, mock_psutil: MagicMock) -> None:
        mock_conn = MagicMock()
        mock_conn.pid = None
        mock_conn.laddr.ip = "192.168.1.50"
        mock_conn.laddr.port = 54321
        mock_conn.raddr = None
        mock_conn.status = "LISTEN"

        mock_psutil.net_connections.return_value = [mock_conn]

        collector = NetworkConnectionsCollector()
        items, health = collector.collect()

        assert len(items) == 1
        assert "local_address" not in items[0]

    @patch("cemi.collectors.network_connections.psutil")
    def test_iteration_error_strings_are_redacted(self, mock_psutil: MagicMock) -> None:
        mock_psutil.net_connections.side_effect = Exception(
            r"Cannot enumerate connections: C:\Users\bob\profile locked"
        )

        collector = NetworkConnectionsCollector()
        items, health = collector.collect()

        assert len(health.errors) >= 1
        for err in health.errors:
            assert "bob" not in err
            assert r"C:\Users\bob" not in err

    @patch("cemi.collectors.network_connections.psutil")
    def test_per_connection_error_strings_are_redacted(self, mock_psutil: MagicMock) -> None:
        class _BrokenConn:
            pid = 1234
            raddr = None
            status = "ESTABLISHED"

            @property
            def laddr(self):  # noqa: ANN201
                raise Exception(
                    r"Failed to read laddr from C:\Users\carol\AppData\sockets: access denied"
                )

        mock_psutil.net_connections.return_value = [_BrokenConn()]

        collector = NetworkConnectionsCollector()
        items, health = collector.collect()

        assert len(health.errors) >= 1
        for err in health.errors:
            assert "carol" not in err
            assert r"C:\Users\carol" not in err

    @patch("cemi.collectors.network_connections.psutil")
    def test_captures_remote_ip_port(self, mock_psutil: MagicMock) -> None:
        mock_conn = MagicMock()
        mock_conn.pid = None
        mock_conn.laddr.ip = "192.168.1.100"
        mock_conn.laddr.port = 49152
        mock_conn.raddr.ip = "52.84.21.14"
        mock_conn.raddr.port = 443
        mock_conn.status = "ESTABLISHED"

        mock_psutil.net_connections.return_value = [mock_conn]

        collector = NetworkConnectionsCollector()
        items, health = collector.collect()

        assert len(items) == 1
        conn = items[0]
        assert conn["remote_address"] == "52.84.21.14"
        assert conn["remote_port"] == 443

    @patch("cemi.collectors.network_connections.psutil")
    def test_handles_none_pid(self, mock_psutil: MagicMock) -> None:
        mock_conn = MagicMock()
        mock_conn.pid = None
        mock_conn.laddr.ip = "127.0.0.1"
        mock_conn.laddr.port = 54321
        mock_conn.raddr = None
        mock_conn.status = "LISTEN"

        mock_psutil.net_connections.return_value = [mock_conn]

        collector = NetworkConnectionsCollector()
        items, health = collector.collect()

        assert len(items) == 1
        conn = items[0]
        assert conn["pid"] is None
        assert conn["process_name"] is None
        assert "exe_path" not in conn
