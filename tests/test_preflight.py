"""Preflight readiness report: `qeuph preflight` and the daemon's own checks.

The report is the single source of truth for "can this build run on this
network with this configuration": the CLI prints it and `Daemon.preflight`
logs its warnings, so a change to one is a change to both.
"""
import dataclasses
import json
import socket
import subprocess
import sys

from qeuph import constants as C
from qeuph.config import MAINNET, REGTEST, TESTNET
from qeuph.core.chain import ChainManager
from qeuph.main import FAIL, OK, WARN, preflight_report


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _net(net, tmp_path, name="d"):
    return net.with_(data_dir=str(tmp_path / name),
                     p2p_port=_free_port(), rpc_port=_free_port())


def _check(report, name):
    return [c for c in report["checks"] if c["name"] == name][0]


class TestReport:
    def test_every_network_passes_with_peers_configured(self, tmp_path):
        for net in (MAINNET, TESTNET, REGTEST):
            n = _net(net, tmp_path, net.name)
            report = preflight_report(n, connect_peers=[("127.0.0.1", 19090)])
            assert report["network"] == net.name
            assert report["ok"], report["warnings"]
            assert _check(report, "genesis")["status"] == OK
            assert _check(report, "emission")["status"] == OK
            # the mainnet genesis must match the pinned checkpoint
            if net.is_mainnet:
                assert "0000000d2f105b23" in _check(report, "genesis")["detail"]

    def test_no_peers_is_a_warning_not_a_failure(self, tmp_path):
        report = preflight_report(_net(MAINNET, tmp_path, "nopeers"))
        assert _check(report, "peers")["status"] == WARN
        assert report["ok"]
        assert any("bootstrap" in w for w in report["warnings"])

    def test_a_busy_port_is_reported(self, tmp_path):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            s.listen(1)
            busy = s.getsockname()[1]
            report = preflight_report(
                _net(REGTEST, tmp_path, "busy"),
                connect_peers=[("127.0.0.1", 1)],
                p2p_port=busy)
            assert _check(report, "p2p port")["status"] == WARN
            assert str(busy) in _check(report, "p2p port")["detail"]

    def test_foreign_data_directory_is_a_failure(self, tmp_path):
        """A regtest store must not be mistaken for a mainnet one."""
        reg = _net(REGTEST, tmp_path, "reg")
        cm = ChainManager(reg)
        cm.close()
        report = preflight_report(
            MAINNET.with_(data_dir=reg.data_dir), connect_peers=[("h", 1)])
        assert _check(report, "chain store")["status"] == FAIL
        assert not report["ok"]

    def test_rpc_exposed_without_auth_is_a_warning(self, tmp_path):
        report = preflight_report(
            _net(MAINNET, tmp_path, "rpc"), connect_peers=[("127.0.0.1", 1)],
            rpc_host="0.0.0.0", rpc_authenticated=False)
        assert _check(report, "rpc auth")["status"] == WARN
        report = preflight_report(
            _net(MAINNET, tmp_path, "rpc2"), connect_peers=[("127.0.0.1", 1)],
            rpc_host="0.0.0.0", rpc_authenticated=True)
        assert _check(report, "rpc auth")["status"] == OK

    def test_data_dir_is_created_and_writable(self, tmp_path):
        n = _net(TESTNET, tmp_path, "fresh")
        report = preflight_report(n, connect_peers=[("127.0.0.1", 1)])
        assert _check(report, "data dir")["status"] == OK
        assert _check(report, "chain store")["status"] == OK


# ---------------------------------------------------------------------------
# the two surfaces that expose the report
# ---------------------------------------------------------------------------
class TestCliCommand:
    def _run(self, *args):
        return subprocess.run([sys.executable, "-m", "qeuph.cli.main",
                               "preflight", *args],
                              capture_output=True, text=True, timeout=120)

    def test_regtest_json_exits_zero(self, tmp_path):
        p = self._run("--network", "regtest", "--data-dir", str(tmp_path / "r"),
                      "--json")
        assert p.returncode == 0, p.stdout + p.stderr
        doc = json.loads(p.stdout)
        assert doc["network"] == "regtest"
        assert doc["ok"] is True
        assert any(c["name"] == "genesis" for c in doc["checks"])

    def test_human_output_lists_checks(self, tmp_path):
        p = self._run("--network", "regtest", "--data-dir", str(tmp_path / "r2"),
                      "--p2p-port", str(_free_port()),
                      "--rpc-port", str(_free_port()))
        assert p.returncode == 0, p.stdout + p.stderr
        assert "preflight" in p.stdout
        assert "genesis" in p.stdout and "emission" in p.stdout
        assert "fail" in p.stdout

    def test_failures_exit_non_zero(self, tmp_path):
        """A foreign chain.db must make the command fail, not just warn."""
        reg = _net(REGTEST, tmp_path, "reg")
        ChainManager(reg).close()
        p = self._run("--network", "mainnet", "--data-dir", reg.data_dir,
                      "--json")
        assert p.returncode == 1
        doc = json.loads(p.stdout)
        assert doc["ok"] is False
        assert any(c["status"] == FAIL for c in doc["checks"])

    def test_mainnet_reports_are_reachable(self, tmp_path):
        p = self._run("--network", "mainnet", "--data-dir", str(tmp_path / "m"),
                      "--json")
        assert p.returncode == 0, p.stdout + p.stderr
        doc = json.loads(p.stdout)
        assert doc["network"] == "mainnet"
        assert _check(doc, "checkpoints")["status"] == WARN
        assert _check(doc, "rpc auth")["status"] == OK


class TestDaemonUsesTheSameReport:
    def test_daemon_warnings_come_from_the_report(self, tmp_path):
        from qeuph.main import Daemon
        n = _net(REGTEST, tmp_path, "d")
        d = Daemon(network=n, connect_peers=[("127.0.0.1", 1)])
        try:
            warnings = d.preflight()
            report = preflight_report(
                n, connect_peers=d.node.connect_peers,
                seed_hosts=d.node.seed_hosts, rpc_host=d.rpc.host,
                rpc_port=d.rpc.port, p2p_port=n.p2p_port,
                data_dir=n.data_dir,
                rpc_authenticated=d.rpc.auth_required)
            assert warnings == report["warnings"]
        finally:
            d.chain.close()

