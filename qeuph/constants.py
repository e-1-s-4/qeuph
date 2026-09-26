"""
Qeuph (QUH) network protocol constants.

Derived from the Qeuph whitepaper:
  * 5 minute block time
  * difficulty retarget every 2048 blocks (~7 days)
  * block reward 50 QUH, multiplied by 2/3 every 210,000 blocks (floored)
  * total supply 31,500,000 QUH (geometric series sum, never exceeded)
  * 8 decimal places (1 QUH = 100,000,000 quphi)
  * ML-DSA-87 signatures, SHA3-512 hashing, Bech32m addresses (HRP "quh")
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------
NAME = "Qeuph"
TICKER = "QUH"
VERSION = "1.1.0"
PROTOCOL_VERSION = 1

# ---------------------------------------------------------------------------
# Value units
# ---------------------------------------------------------------------------
# Smallest unit: 1 quphi.  1 QUH = 10^8 quphi.
QUPHI_PER_QUH = 100_000_000
DECIMALS = 8

# Total supply cap: 31,500,000 QUH = 3.15e15 quphi.
# The two-thirding schedule sums to exactly this amount before floor losses;
# floor rounding keeps the true emission at or slightly below the cap.
MAX_SUPPLY_QUH = 31_500_000
MAX_SUPPLY = MAX_SUPPLY_QUH * QUPHI_PER_QUH

# ---------------------------------------------------------------------------
# Reward schedule ("two-thirding")
# ---------------------------------------------------------------------------
REWARD_INITIAL = 50 * QUPHI_PER_QUH      # 50 QUH in quphi
REWARD_INTERVAL = 210_000                # blocks per epoch
REWARD_NUMERATOR = 2                     # reward *= 2/3 at each epoch
REWARD_DENOMINATOR = 3

# ---------------------------------------------------------------------------
# Consensus / PoW
# ---------------------------------------------------------------------------
BLOCK_TIME_SECONDS = 300                 # 5 minutes
RETARGET_INTERVAL = 2048                 # ~7.1 days at 5 min blocks
RETARGET_BOUND_FACTOR = 4                # clamp adjustment to 1/4x .. 4x
MAX_TARGET_SHIFT_UP = 4                  # max difficulty *4 per retarget
GENESIS_BITS = 0x3D0FFFFF                # compact initial target (mainnet)
                                         # target = 2^484: ~4.5 min blocks at
                                         # 1 MH/s network hashrate at launch;
                                         # retarget settles within 2048 blocks
MAX_FUTURE_BLOCK_SECONDS = 2 * 3600      # 2h clock-drift tolerance

# Compact target bounds (BTC-style "bits" field over the 512-bit hash space)
# Easiest: 0x407FFFFF -> target ~2^511 (p(success) ~ 1/2 per hash)
# Hardest: 0x01010000 -> target 1
MIN_BITS = 0x407FFFFF                 # easiest allowed (max target)
MAX_BITS = 0x01010000                 # hardest allowed (target 1)

# ---------------------------------------------------------------------------
# Transaction / block limits
# ---------------------------------------------------------------------------
TX_VERSION = 1
BLOCK_VERSION = 1
COINBASE_MATURITY = 100                  # blocks before coinbase is spendable
MAX_BLOCK_SIZE = 2_000_000               # serialized transaction bytes
MAX_TX_SIZE = 400_000
MIN_RELAY_FEE_RATE = 1000                # quphi per 1000 bytes
MAX_MEMPOOL_SIZE = 200 * 1024 * 1024     # bytes of serialized txs
MAX_ORPHAN_BLOCKS = 128
MTP_WINDOW = 11                           # median-time-past window (blocks)
MEMPOOL_EVICT_AGE = 3 * 24 * 3600        # drop txs older than 3 days

# ---------------------------------------------------------------------------
# Peer-to-peer housekeeping
# ---------------------------------------------------------------------------
PEER_PING_INTERVAL = 30                  # seconds between keepalive pings
PEER_IDLE_TIMEOUT = 180                  # drop a peer silent for this long
PEER_MSG_BUDGET = 600                    # max messages per peer per second
PEER_MSG_BURST = 1500                    # token bucket burst size
MAX_FRAME_BUFFER = 32 * 1024 * 1024      # per-peer inbound frame buffer bound
TARGET_OUTBOUND_PEERS = 8                # maintained by the discovery task
PEER_RECONNECT_INTERVAL = 15             # seconds between reconnect sweeps
KNOWN_ADDR_LIMIT = 4096                  # bounded peer address cache
SYNC_TICK_INTERVAL = 2.0                 # seconds between sync driver passes
STALLED_SYNC_TIMEOUT = 30                # seconds without progress -> re-request
MAX_INV = 4096                           # per inv/getdata message
MAX_HEADERS = 512                        # per headers message
MAX_ADDR_RELAY = 1024                    # per addr message

# Signature sizes (ML-DSA-87) - used for sanity checks
MLDSA_PK_SIZE = 2592
MLDSA_SIG_SIZE = 4627

# ---------------------------------------------------------------------------
# Addresses
# ---------------------------------------------------------------------------
ADDRESS_HRP_MAINNET = "quh"
ADDRESS_HRP_TESTNET = "tquh"
ADDRESS_HRP_REGTEST = "rquh"
ADDRESS_HASH_SIZE = 64                   # double SHA3-512 digest used directly

# ---------------------------------------------------------------------------
# Network magic & ports (mainnet)
# ---------------------------------------------------------------------------
MAGIC_BYTES = b"\x51\x55\x48\x21"        # "QUH!"
DEFAULT_P2P_PORT = 19090
DEFAULT_RPC_PORT = 19091
DEFAULT_RPC_HOST = "127.0.0.1"

# DNS seed placeholders (populated at launch)
DNS_SEEDS_MAINNET = []
DNS_SEEDS_TESTNET = ["testnet-seed.qeuph.example"]

# ---------------------------------------------------------------------------
# Blockchain identity strings (for message prefixes / seed derivation)
# ---------------------------------------------------------------------------
# Qeuph genesis is scheduled for 2026-10-01 00:00:00 UTC
GENESIS_TIMESTAMP = 1790812800
GENESIS_MESSAGE = ("26/Sep/2026 The quantum era demands quantum-resistant money. "
                   "Qeuph: ML-DSA-87 + SHA3-512, two-thirding to 31.5M QUH.")

# Checkpoint seeds: block height -> block hash (64 bytes)
CHECKPOINTS = {
    0: bytes.fromhex(
        "0000000d2f105b239cd085e9d4bd7fa087dc6a085ee37b3842d539ab9c974247"
        "fa8c4000695807b0a5d306d40c713e32b130387f72b64a00bf2b0c9953b179b1"
    )
}
