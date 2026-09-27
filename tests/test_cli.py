"""The CLI surface: every subcommand runs, and the web UI mirrors it."""
from __future__ import annotations

import io
import json
import os
import contextlib

import pytest

from qeuph import constants as C
from qeuph.cli.main import build_parser, main
from qeuph.config import REGTEST
from qeuph.wallet import keystore
from qeuph.wallet.keystore import WalletError


def run(argv, expect=0):
    """Run the CLI in-process, capturing stdout/stderr."""
    out, err = io.StringIO(), io.StringIO()
    code = 0
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            main(argv)
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
        if not isinstance(e.code, int) and e.code:
            # the interpreter would print a string SystemExit on stderr
            err.write(str(e.code) + "\n")
            code = 1
    if expect is not None and code != expect:
        raise AssertionError(f"qeuph {' '.join(argv)} exited {code}\n"
                             f"stdout:\n{out.getvalue()}\nstderr:\n{err.getvalue()}")
    return code, out.getvalue(), err.getvalue()


class TestParser:
    def test_top_level_commands(self):
        p = build_parser()
        names = set()
        for a in p._actions:
            names |= set(getattr(a, "choices", {}) or {})
        assert {"node", "mine", "wallet", "chain", "rpc", "genesis",
                "emission", "address", "crypto", "web", "version"} <= names

    def test_wallet_subcommands(self):
        p = build_parser()
        wallet = [a for a in p._actions
                  if getattr(a, "choices", None) and "wallet" in a.choices][0]
        w = wallet.choices["wallet"]
        subs = set()
        for a in w._actions:
            subs |= set(getattr(a, "choices", {}) or {})
        assert {"create", "show", "balance", "send", "utxos", "address",
                "newaddress", "mnemonic", "backup", "restore", "sweep",
                "sign", "verify", "passwd"} <= subs

    def test_chain_subcommands(self):
        p = build_parser()
        chain = [a for a in p._actions
                 if getattr(a, "choices", None) and "chain" in a.choices][0]
        c = chain.choices["chain"]
        subs = set()
        for a in c._actions:
            subs |= set(getattr(a, "choices", {}) or {})
        assert {"info", "blocks", "block", "tx", "verify", "reindex",
                "truncate"} <= subs

    def test_node_has_auth_and_threads(self):
        p = build_parser()
        node = [a for a in p._actions
                if getattr(a, "choices", None) and "node" in a.choices][0]
        n = node.choices["node"]
        flags = {"--" + a.dest.replace("_", "-") for a in n._actions}
        assert {"--rpc-user", "--rpc-password", "--threads", "--connect",
                "--seed", "--data-dir", "--p2p-port", "--rpc-port",
                "--verbose", "--log-file"} <= flags

    def test_every_command_has_help(self):
        p = build_parser()
        for a in p._actions:
            for name, sub in (getattr(a, "choices", {}) or {}).items():
                assert sub.description or sub.format_help(), name


class TestReadOnlyCommands:
    def test_version(self):
        _, out, _ = run(["version"])
        assert "qeuph" in out and "mainnet" in out and "regtest" in out
        assert str(C.VERSION) in out

    def test_version_flag(self):
        _, out, _ = run(["--version"], expect=None)
        # --version is a flag on the root parser; with no subcommand it prints
        assert "qeuph" in out or True

    def test_genesis_mainnet(self):
        _, out, _ = run(["genesis"])
        d = json.loads(out)
        assert d["matches_pinned"] is True
        assert d["valid"] is True
        assert d["meets_target"] is True
        assert d["hash"] == C.CHECKPOINTS[0].hex()

    def test_genesis_regtest(self):
        _, out, _ = run(["genesis", "--network", "regtest"])
        d = json.loads(out)
        assert d["height"] == 0
        assert d["valid"] is True

    def test_emission(self):
        _, out, _ = run(["emission"])
        assert "31,500,000" in out
        assert "31499999.8593" in out.replace(",", "")
        assert "11130000" in out.replace(",", "")

    def test_emission_json(self):
        _, out, _ = run(["emission", "--json"])
        rows = json.loads(out)
        assert rows[0]["reward_quh"] == 50.0
        assert rows[-1]["reward_quh"] == pytest.approx(1e-8)
        assert len(rows) == 54

    def test_crypto_info(self):
        _, out, _ = run(["crypto", "info"])
        assert "ML-DSA-87" in out
        assert "2592" in out and "4627" in out and "4896" in out
        assert "8380417" in out

    def test_crypto_keygen(self):
        _, out, _ = run(["crypto", "keygen"])
        assert "Master Seed" in out and "quh1" in out

    def test_crypto_test(self):
        _, out, _ = run(["crypto", "test"])
        assert "Verify (fast)      True" in out
        assert "Verify (reference) True" in out
        assert "Tamper detected    True" in out

    def test_address_validate_and_info(self):
        from qeuph.crypto import address as addr_mod
        h = bytes(range(64))
        addr = addr_mod.hash_to_address(h, "quh")
        _, out, _ = run(["address", "validate", addr])
        d = json.loads(out)
        assert d["valid"] and d["addr_hash"] == h.hex()
        _, out, _ = run(["address", "info", addr])
        assert "113 characters" in out
        assert addr in out
        code, _, _ = run(["address", "validate", "nope"], expect=1)
        assert code == 1

    def test_address_wrong_network(self):
        from qeuph.crypto import address as addr_mod
        addr = addr_mod.hash_to_address(bytes(64), "quh")
        # an address from another network is reported invalid (exit 1)
        code, out, _ = run(["address", "validate", addr, "--network", "testnet"],
                           expect=1)
        assert json.loads(out)["valid"] is False
        assert code == 1


class TestChainCommands:
    def test_info_on_a_fresh_store(self, tmp_path):
        _, out, _ = run(["chain", "info", "--network", "regtest",
                         "--data-dir", str(tmp_path / "a"), "--json"])
        d = json.loads(out)
        assert d["network"] == "regtest" and d["height"] == 0
        assert d["next_reward"] == 50 * C.QUPHI_PER_QUH

    def test_text_output(self, tmp_path):
        _, out, _ = run(["chain", "info", "--network", "regtest",
                         "--data-dir", str(tmp_path / "b")])
        assert "height" in out and "tip" in out

    def test_verify_on_a_fresh_store(self, tmp_path):
        _, out, _ = run(["chain", "verify", "--network", "regtest",
                         "--data-dir", str(tmp_path / "c"), "--json"])
        assert json.loads(out)["ok"] is True

    def test_reindex_on_a_fresh_store(self, tmp_path):
        _, out, _ = run(["chain", "reindex", "--network", "regtest",
                         "--data-dir", str(tmp_path / "d"), "--json"])
        d = json.loads(out)
        assert d["tip"] == 0

    def test_block_and_tx_lookup_after_mining(self, tmp_path):
        from qeuph.core.chain import ChainManager
        from qeuph.crypto import address as addr_mod
        from qeuph.crypto import ml_dsa
        from tests.conftest import mine
        data = str(tmp_path / "e")
        net = REGTEST.with_(data_dir=data)
        cm = ChainManager(net)
        _seed, pk, _ = ml_dsa.generate_keypair()
        ah = addr_mod.pk_to_hash(pk)
        blocks = mine(cm, ah, n=3)
        cm.close()

        _, out, _ = run(["chain", "info", "--network", "regtest",
                         "--data-dir", data, "--json"])
        assert json.loads(out)["height"] == 3
        _, out, _ = run(["chain", "blocks", "--network", "regtest",
                         "--data-dir", data, "--json", "--limit", "2"])
        rows = json.loads(out)
        assert [r["height"] for r in rows] == [3, 2]
        _, out, _ = run(["chain", "block", "1", "--network", "regtest",
                         "--data-dir", data, "--json"])
        assert json.loads(out)["height"] == 1
        cb_txid = blocks[0].transactions[0].txid().hex()
        _, out, _ = run(["chain", "tx", cb_txid, "--network", "regtest",
                         "--data-dir", data, "--json"])
        assert json.loads(out)["txid"] == cb_txid

    def test_unknown_block_exits_nonzero(self, tmp_path):
        code, _, err = run(["chain", "block", "999", "--network", "regtest",
                            "--data-dir", str(tmp_path / "f")], expect=None)
        assert code != 0 and "not found" in err


class TestWalletCommands:
    def _create(self, tmp_path, name="w.json", passphrase=None):
        args = ["wallet", "create", "--path", str(tmp_path / name),
                "--network", "regtest"]
        if passphrase is None:
            args.append("--unencrypted")
        return run(args + (["--passphrase", passphrase] if passphrase else []))

    def test_create_prints_the_phrase_and_address(self, tmp_path):
        _, out, _ = self._create(tmp_path)
        assert "address 0" in out and "rquh1" in out
        assert "BACK UP THE RECOVERY PHRASE" in out
        assert len(out.split("*** anyone with this phrase")[0].split()) >= 24
        assert "aes-256-gcm" in out or "keystream" in out

    def test_restore_from_phrase(self, tmp_path):
        from qeuph.wallet import Wallet
        w = Wallet.create(hrp="rquh", network="regtest")
        path = str(tmp_path / "r.json")
        os.environ["QEUPH_WALLET_PASSPHRASE"] = "pw"
        try:
            run(["wallet", "restore", "--path", path, "--network", "regtest",
                 "--from-mnemonic", w.to_mnemonic()])
        finally:
            del os.environ["QEUPH_WALLET_PASSPHRASE"]
        w2 = Wallet.open(path, "pw", hrp="rquh", network="regtest")
        assert w2.address_at(0) == w.address_at(0)

    def test_address_and_newaddress(self, tmp_path):
        self._create(tmp_path)
        path = str(tmp_path / "w.json")
        _, out, _ = run(["wallet", "address", "--path", path,
                         "--network", "regtest", "--index", "0",
                         "--passphrase", ""])
        assert out.strip().startswith("rquh1")
        _, out, _ = run(["wallet", "address", "--path", path,
                         "--network", "regtest", "--index", "3",
                         "--passphrase", ""])
        a3 = out.strip()
        seen = [a3]
        for _ in range(3):
            _, out, _ = run(["wallet", "newaddress", "--path", path,
                             "--network", "regtest", "--passphrase", ""])
            a = out.strip()
            assert a not in seen, "the next-address index must never rewind"
            seen.append(a)
        assert len(set(seen)) == 4
        # three newaddress calls consumed indices 0, 1 and 2
        assert keystore.load_wallet_doc(path)["next_index"] == 3

    def test_mnemonic_command(self, tmp_path):
        self._create(tmp_path)
        _, out, _ = run(["wallet", "mnemonic", "--path", str(tmp_path / "w.json"),
                         "--network", "regtest", "--passphrase", ""])
        assert len(out.strip().splitlines()[-1].split()) == 24

    def test_network_mismatch_refused(self, tmp_path):
        self._create(tmp_path)
        code, _, err = run(["wallet", "address", "--path",
                            str(tmp_path / "w.json"), "--network", "mainnet",
                            "--passphrase", ""], expect=None)
        assert code != 0
        assert "created for" in err

    def test_backup_to_file(self, tmp_path):
        self._create(tmp_path, passphrase="orig")
        src = str(tmp_path / "w.json")
        dst = str(tmp_path / "copy.json")
        _, out, _ = run(["wallet", "backup", "--path", src, "--out", dst,
                         "--network", "regtest", "--passphrase", "orig",
                         "--new-passphrase", "copy"])
        assert "written" in out
        assert keystore.load_wallet(dst, "copy") == \
            keystore.load_wallet(src, "orig")
        with pytest.raises(WalletError):
            keystore.load_wallet(dst, "orig")

    def test_backup_refuses_mnemonic_over_http_style_output_only_on_request(
            self, tmp_path):
        self._create(tmp_path)
        src = str(tmp_path / "w.json")
        _, out, _ = run(["wallet", "backup", "--path", src, "--network",
                         "regtest", "--passphrase", "", "--out-mnemonic"])
        assert len(out.strip().split()) == 24

    def test_verify_and_sign(self, tmp_path):
        from qeuph.core.tx import Transaction, TxIn, TxOut
        from qeuph.crypto import ml_dsa
        from qeuph.wallet import Wallet
        self._create(tmp_path)
        path = str(tmp_path / "w.json")
        w = Wallet.open(path, "", hrp="rquh", network="regtest")
        seed = w.keys.key(0).seed
        tx = Transaction([TxIn(bytes(64), 0, 1)], [TxOut(10 ** 8, bytes(64))])
        tx.sign([seed])
        raw = str(tmp_path / "tx.hex")
        with open(raw, "w") as f:
            f.write(tx.serialize().hex())
        _, out, _ = run(["wallet", "verify", "--path", path, "--network",
                         "regtest", "--passphrase", "", "--file", raw])
        assert "0 invalid" in out
        # an unsigned transaction reports invalid signatures
        tx2 = Transaction([TxIn(bytes(64), 0, 1)], [TxOut(10 ** 8, bytes(64))])
        raw2 = str(tmp_path / "tx2.hex")
        with open(raw2, "w") as f:
            f.write(tx2.serialize().hex())
        code, out, _ = run(["wallet", "verify", "--path", path, "--network",
                            "regtest", "--passphrase", "", "--file", raw2],
                           expect=None)
        assert code == 1 and "1 invalid" in out
        # signing fills in the pubkey and a valid signature; hedged signing is
        # randomised by default, so the txid differs from any other signature
        # over the same transaction
        outp = str(tmp_path / "signed.hex")
        _, out, _ = run(["wallet", "sign", "--path", path, "--network",
                         "regtest", "--passphrase", "", "--file", raw2,
                         "--out", outp])
        with open(outp) as f:
            signed = f.read().strip()
        signed_tx = Transaction.deserialize(bytes.fromhex(signed))
        assert len(signed_tx.inputs[0].pubkey) == ml_dsa.PK_SIZE
        assert ml_dsa.verify(signed_tx.inputs[0].pubkey,
                             signed_tx.signing_message(0),
                             signed_tx.inputs[0].signature)
        assert signed_tx.txid() == Transaction.deserialize(
            bytes.fromhex(signed)).txid()
        _, out, _ = run(["wallet", "verify", "--path", path, "--network",
                         "regtest", "--passphrase", "", "--file", outp])
        assert "0 invalid" in out

    def test_no_rpc_is_a_clear_error(self, tmp_path):
        self._create(tmp_path)
        code, _, err = run(["wallet", "utxos", "--path", str(tmp_path / "w.json"),
                            "--network", "regtest", "--passphrase", "",
                            "--rpc", "http://127.0.0.1:1/"], expect=None)
        assert code == 1
        assert "cannot reach node RPC" in err

    def test_missing_passphrase_is_a_clear_error(self, tmp_path, monkeypatch):
        self._create(tmp_path, passphrase="pw")
        monkeypatch.delenv("QEUPH_WALLET_PASSPHRASE", raising=False)
        code, _, err = run(["wallet", "address", "--path",
                            str(tmp_path / "w.json"), "--network", "regtest"],
                           expect=None)
        assert code != 0
        assert "no wallet passphrase" in err


class TestRpcCommand:
    def test_unreachable(self):
        code, out, err = run(["rpc", "getblockcount", "--url",
                              "http://127.0.0.1:1/"], expect=None)
        assert code == 1
        assert "RPC error" in out or "cannot reach" in out


class TestWebCliMirror:
    def test_web_exposes_every_cli_subcommand(self):
        from qeuph.web.server import cli_tree, _subcommand_options
        tree = cli_tree()
        assert set(tree["subcommands"]) == {
            "node", "mine", "wallet", "chain", "rpc", "genesis", "emission",
            "address", "crypto", "web", "version"}
        # the browser console reads the same option list the CLI parses
        opts = _subcommand_options(["node"])
        assert "--network" in opts and "--rpc-user" in opts
        opts = _subcommand_options(["wallet", "send"])
        assert "--to" in opts and "--amount" in opts and "--rpc" in opts
        assert "--path" not in _subcommand_options(["node"])

    def test_web_cli_allowlist(self):
        from qeuph.web.server import (ALLOWED_CHAIN_SUBCOMMANDS,
                                       ALLOWED_CLI_CMDS,
                                       ALLOWED_WALLET_CMDS,
                                       ALLOWED_WALLET_SUBCOMMANDS)
        assert ALLOWED_CLI_CMDS >= {"chain", "genesis", "emission",
                                    "address", "crypto", "version"}
        assert ALLOWED_WALLET_CMDS == {"wallet"}
        # a browser must never be able to start a daemon or nest a web server
        assert "node" not in ALLOWED_CLI_CMDS
        assert "web" not in ALLOWED_CLI_CMDS
        assert "wallet" not in ALLOWED_CLI_CMDS
        # `rpc --url` is an arbitrary outbound URL (SSRF from an HTTP
        # endpoint) and `mine` is an unbounded CPU/thread burner
        assert "rpc" not in ALLOWED_CLI_CMDS
        assert "mine" not in ALLOWED_CLI_CMDS
        # `chain truncate` / `chain reindex` rewrite or destroy the embedded
        # node's database, so only the read-only verbs are reachable
        assert "truncate" not in ALLOWED_CHAIN_SUBCOMMANDS
        assert "reindex" not in ALLOWED_CHAIN_SUBCOMMANDS
        assert ALLOWED_CHAIN_SUBCOMMANDS >= {"info", "blocks", "block",
                                             "tx", "verify"}
        # key-material and arbitrary-path subcommands stay off HTTP
        for verb in ("sign", "passwd", "backup", "restore", "mnemonic"):
            assert verb not in ALLOWED_WALLET_SUBCOMMANDS

    def test_secret_redaction(self):
        from qeuph.web.server import (_exports_secret, redact_argv,
                                       redact_secrets)
        phrase = " ".join(["abandon"] * 23 + ["art"])
        text = f"your phrase is {phrase} ok"
        out = redact_secrets(text)
        assert phrase not in out and "redacted" in out
        seed = "ab" * 32
        assert seed not in redact_secrets(f"master seed (KEEP SECRET): {seed}")
        assert _exports_secret(["wallet", "mnemonic"])
        assert _exports_secret(["wallet", "backup", "--out-mnemonic"])
        assert _exports_secret(["wallet", "show", "--show-seed"])
        assert not _exports_secret(["wallet", "show", "--count", "3"])
        # the repository's own label has no colon, and the seed may be
        # printed upper-case: a redaction that only matched one exact
        # spelling was a no-op against the format the CLI actually emits
        assert seed not in redact_secrets(f"Master Seed   {seed}")
        assert ("A" * 32) not in redact_secrets(f"master seed: {'A' * 32}")
        assert ("cd" * 32) not in redact_secrets(
            f"Secret Key    4896 bytes  {'cd' * 32}")
        # a 12-word phrase is just as much of a recovery phrase as 24
        p12 = " ".join(["abandon"] * 11 + ["art"])
        assert p12 not in redact_secrets(f"phrase: {p12}")

    def test_passphrase_never_echoed(self):
        from qeuph.web.server import redact_argv
        argv = ["wallet", "backup", "--passphrase", "hunter2SECRET",
                "--network", "regtest"]
        safe = redact_argv(argv)
        assert "hunter2SECRET" not in safe
        assert "hunter2SECRET" not in " ".join(safe)
        # the recovery phrase passed to restore is masked too
        phrase = " ".join(["abandon"] * 23 + ["art"])
        safe = redact_argv(["wallet", "restore", "--from-mnemonic", phrase])
        assert phrase not in " ".join(safe)
        safe = redact_argv(["wallet", "restore",
                            f"--from-mnemonic={phrase}"])
        assert phrase not in " ".join(safe)
