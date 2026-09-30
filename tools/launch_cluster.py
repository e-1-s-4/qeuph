#!/usr/bin/env python3
"""Multi-Node Cluster Orchestrator for Qeuph (QUH).

Launches a coordinated multi-node P2P mesh cluster with seed peer discovery,
JSON-RPC interfaces, and optional Web Explorer UI in pure Python.

Usage:
    python3 tools/launch_cluster.py [--network mainnet|testnet|regtest] [--nodes 3] [--web]
"""
from __future__ import annotations

import argparse
import os
import shutil
import signal
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(
        description="Launch a coordinated Qeuph multi-node P2P cluster."
    )
    parser.add_argument("--network", default="mainnet",
                        choices=["mainnet", "testnet", "regtest"],
                        help="Network profile (default: mainnet)")
    parser.add_argument("--nodes", type=int, default=3,
                        help="Number of node instances to launch (default: 3)")
    parser.add_argument("--data-root", default="/tmp/qeuph-cluster",
                        help="Base directory for node state")
    parser.add_argument("--base-p2p", type=int, default=19090,
                        help="P2P port for Node 0 (seed node)")
    parser.add_argument("--base-rpc", type=int, default=19091,
                        help="RPC port for Node 0")
    parser.add_argument("--web", action="store_true",
                        help="Also start the Web Explorer UI attached to Node 0")
    parser.add_argument("--web-port", type=int, default=3000,
                        help="Web server HTTP port (default: 3000)")
    args = parser.parse_args()

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ, PYTHONPATH=root)

    print("=" * 66)
    print(f"  Qeuph (QUH) {args.network.upper()} Multi-Node Cluster Orchestrator")
    print(f"  Nodes: {args.nodes} | Base P2P: {args.base_p2p} | Base RPC: {args.base_rpc}")
    print("=" * 66)

    procs: list[subprocess.Popen] = []

    def cleanup(*_):
        print("\n[cluster] Shutting down all cluster nodes cleanly...")
        for p in procs:
            if p.poll() is None:
                p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except Exception:
                p.kill()
        print("[cluster] All node processes terminated.")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    try:
        # Launch Node 0 (Bootstrap Seed Node)
        seed_dir = os.path.join(args.data_root, f"{args.network}-node0")
        os.makedirs(seed_dir, exist_ok=True)
        seed_p2p = args.base_p2p
        seed_rpc = args.base_rpc

        print(f"\n[node 0] Bootstrapping seed node...")
        print(f"         Data: {seed_dir}")
        print(f"         P2P:  0.0.0.0:{seed_p2p} (seed)")
        print(f"         RPC:  127.0.0.1:{seed_rpc}")

        cmd0 = [
            sys.executable, "-m", "qeuph.cli.main", "node",
            "--network", args.network,
            "--datadir", seed_dir,
            "--listen", f"0.0.0.0:{seed_p2p}",
            "--rpc", f"127.0.0.1:{seed_rpc}",
        ]
        p0 = subprocess.Popen(cmd0, cwd=root, env=env)
        procs.append(p0)

        # Allow seed node to bind ports
        time.sleep(1.5)

        # Launch Peer Nodes (Node 1 .. N-1)
        for i in range(1, args.nodes):
            node_dir = os.path.join(args.data_root, f"{args.network}-node{i}")
            os.makedirs(node_dir, exist_ok=True)
            node_p2p = args.base_p2p + i * 10
            node_rpc = args.base_rpc + i * 10

            print(f"\n[node {i}] Launching peer node...")
            print(f"         Data:    {node_dir}")
            print(f"         P2P:     0.0.0.0:{node_p2p}")
            print(f"         RPC:     127.0.0.1:{node_rpc}")
            print(f"         Dials:   127.0.0.1:{seed_p2p} (Node 0)")

            cmd_i = [
                sys.executable, "-m", "qeuph.cli.main", "node",
                "--network", args.network,
                "--datadir", node_dir,
                "--listen", f"0.0.0.0:{node_p2p}",
                "--rpc", f"127.0.0.1:{node_rpc}",
                "--connect", f"127.0.0.1:{seed_p2p}",
            ]
            pi = subprocess.Popen(cmd_i, cwd=root, env=env)
            procs.append(pi)
            time.sleep(0.5)

        # Optional Web UI instance
        if args.web:
            print(f"\n[web ui] Launching Web Explorer on http://127.0.0.1:{args.web_port}/")
            print(f"         Attached to Seed Node RPC: http://127.0.0.1:{seed_rpc}/")
            web_cmd = [
                sys.executable, "-m", "qeuph.web.server",
                "--network", args.network,
                "--port", str(args.web_port),
                "--embedded-node", "off",
                "--remote-rpc", f"http://127.0.0.1:{seed_rpc}",
            ]
            p_web = subprocess.Popen(web_cmd, cwd=root, env=env)
            procs.append(p_web)

        print("\n" + "=" * 66)
        print("  CLUSTER RUNNING (Press Ctrl+C to stop all nodes)")
        print("=" * 66)

        while True:
            for i, p in enumerate(procs):
                code = p.poll()
                if code is not None:
                    print(f"\n[warning] Process #{i} exited unexpectedly with code {code}")
            time.sleep(2)

    except KeyboardInterrupt:
        cleanup()


if __name__ == "__main__":
    main()
