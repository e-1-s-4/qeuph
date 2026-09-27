/* Qeuph node explorer - UI logic.
 *
 * Every request goes to the same HTTP API the node documents; read paths use
 * /api/* views and write paths either /api/rpc (the real JSON-RPC dispatch) or
 * /api/cli and /api/wallet (the real `qeuph` subcommands).  No UI-only code
 * path exists, so nothing here can claim a capability the node lacks.
 */
'use strict';

const $ = (id) => document.getElementById(id);
const state = { status: null, tab: 'dashboard', timer: null };

/* ------------------------------------------------------------------ utils */
function fmt(n, d = 2) {
  if (n === null || n === undefined || Number.isNaN(n)) return '—';
  if (typeof n !== 'number') return String(n);
  if (n !== 0 && (Math.abs(n) < 1e-4 || Math.abs(n) >= 1e12)) return n.toExponential(3);
  return n.toLocaleString(undefined, { minimumFractionDigits: d, maximumFractionDigits: d });
}
function quh(quphi) { return (quphi / 1e8).toLocaleString(undefined, { minimumFractionDigits: 8, maximumFractionDigits: 8 }); }
function shortHash(h) { return h ? h.slice(0, 20) + '…' + h.slice(-10) : '—'; }
function shortAddr(a) { return a ? a.slice(0, 16) + '…' + a.slice(-8) : '—'; }
function ago(ts) {
  if (!ts) return '—';
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 90) return Math.round(s) + 's ago';
  if (s < 5400) return Math.round(s / 60) + 'm ago';
  if (s < 172800) return Math.round(s / 3600) + 'h ago';
  return Math.round(s / 86400) + 'd ago';
}
function esc(s) {
  return String(s === null || s === undefined ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
function pretty(v) { return JSON.stringify(v, null, 2); }
function setText(id, v) { const e = $(id); if (e) e.textContent = v; }
function setHtml(id, v) { const e = $(id); if (e) e.innerHTML = v; }

async function api(path, opts) {
  const res = await fetch(path, opts);
  const txt = await res.text();
  let doc;
  try { doc = JSON.parse(txt); } catch (e) { throw new Error('bad JSON: ' + txt.slice(0, 200)); }
  if (!res.ok && doc && doc.error) throw new Error(doc.error);
  return doc;
}
function postJSON(path, body) {
  return api(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
}
function toast(msg, bad) {
  const out = $('cli-out');
  if (out) { out.textContent = msg; out.className = 'out ' + (bad ? 'note bad' : ''); }
}

/* ------------------------------------------------------------------ tabs */
const TAB_LOADERS = {
  dashboard: loadDashboard,
  blocks: loadBlocks,
  mempool: loadMempool,
  wallet: loadWallet,
  miner: loadMiner,
  emission: loadEmission,
  crypto: loadCrypto,
  console: loadConsole,
  about: loadAbout,
};

function showTab(name) {
  state.tab = name;
  document.querySelectorAll('section.tab').forEach((s) => s.classList.add('hidden'));
  $('tab-' + name).classList.remove('hidden');
  document.querySelectorAll('#tabs button').forEach((b) =>
    b.classList.toggle('active', b.dataset.tab === name));
  (TAB_LOADERS[name] || (() => {}))();
}

function wireTabs() {
  document.querySelectorAll('#tabs button').forEach((b) =>
    b.addEventListener('click', () => showTab(b.dataset.tab)));
}

function autoRefresh(on) {
  if (state.timer) { clearInterval(state.timer); state.timer = null; }
  if (on) state.timer = setInterval(poll, 3000);
}

/* ------------------------------------------------------------------ status */
async function poll() {
  try {
    const s = await api('/api/status');
    state.status = s;
    renderStatus(s);
  } catch (e) { /* keep the last render */ }
}

function renderStatus(s) {
  setText('brand-net', `${s.network} · ${s.hrp}1…`);
  setText('pill-backend', `ML-DSA-87 · ${s.backend}`);
  setText('pill-peers', `peers ${s.peers}`);
  const sync = $('pill-sync');
  if (sync) {
    sync.textContent = s.mining ? 'mining' : (s.synced ? 'synced' : 'catching up');
    sync.className = 'pill ' + (s.mining ? 'live' : (s.synced ? 'ok' : 'warn'));
  }
  setText('s-height', s.height);
  setText('s-tip', shortHash(s.best_hash));
  setText('s-diff', s.difficulty < 1 ? s.difficulty.toExponential(2) : fmt(s.difficulty, 2));
  setText('s-bits', 'bits ' + s.bits);
  setText('s-reward', s.reward_quh.toFixed(8).replace(/0+$/, '').replace(/\.$/, '.0'));
  setText('s-epoch', `epoch ${s.epoch} of 54`);
  setText('s-mempool', s.mempool_count);
  setText('s-mempool-bytes', fmt(s.mempool_bytes, 0) + ' bytes');
  setText('s-tiphash', s.best_hash);
  setText('s-work', s.chainwork);
  setText('s-mtp', s.mediantime + (s.mediantime ? ' (' + ago(s.mediantime) + ')' : ''));
  setText('s-genesis', s.genesis_hash);
  setText('s-rpc', s.rpc_url || '—');
  setText('s-peers', s.peers);
  setText('s-utxos', fmt(s.utxos, 0));
  setText('s-reorg', `${s.reorgs} / ${s.orphans}`);
  setText('s-datadir', s.data_dir);
  if ($('netpick').value !== s.network) $('netpick').value = s.network;
  if (state.tab === 'miner') renderMiner(s);
  if (state.tab === 'emission') loadEmission();
}

/* --------------------------------------------------------------- dashboard */
async function loadDashboard() {
  await poll();
  autoRefresh(true);
  const e = await api('/api/emission');
  const exact = e.exact_quh, cap = 31.5e6;
  setText('e-text', `${fmt(exact, 4)} / ${fmt(cap, 0)} QUH issued (${((exact / cap) * 100).toFixed(6)}%)`);
  $('e-bar').style.width = Math.min(100, (exact / cap) * 100) + '%';
  setText('e-exact', fmt(exact, 4) + ' QUH');
  setText('e-epoch', 'epoch ' + (state.status ? state.status.epoch : '—') + ' of ' + e.epochs);
  setText('e-count', e.epochs + ' paying epochs');
  setText('e-final', 'height ' + fmt(e.final_reward_height, 0));
  const rows = await api('/api/blocks?limit=8');
  setHtml('dash-blocks', blockRows(rows.blocks));
}

function blockRows(blocks) {
  if (!blocks || !blocks.length) return '<tr><td colspan="7" class="dimmer">no blocks yet — mine one from the Miner tab</td></tr>';
  return blocks.map((b) => `<tr class="clickable" onclick="showBlock(${b.height})">
    <td class="accent">${b.height}</td>
    <td class="dim">${ago(b.timestamp)}</td>
    <td class="right">${b.tx_count}</td>
    <td class="right dim">${fmt(b.size, 0)}</td>
    <td class="right">${b.miner_payout !== undefined ? quh(b.miner_payout).replace(/0+$/, '') + ' QUH' : '—'}</td>
    <td class="mono-sm">${b.miner_address ? shortAddr(b.miner_address) : '—'}</td>
    <td class="hash">${shortHash(b.hash)}</td></tr>`).join('');
}

/* ------------------------------------------------------------------ blocks */
async function loadBlocks() {
  const limit = parseInt($('blocks-limit').value, 10) || 15;
  const r = await api('/api/blocks?limit=' + limit);
  setHtml('blocks-body', blockRows(r.blocks));
}

async function showBlock(h) {
  try {
    const b = await api('/api/block/' + h);
    $('blocks-detail-out').textContent = pretty(b);
  } catch (e) { toast('block: ' + e.message, true); }
}

/* ----------------------------------------------------------------- mempool */
async function loadMempool() {
  const r = await api('/api/mempool');
  setText('mp-count', r.count);
  setText('mp-bytes', fmt(r.bytes, 0) + ' / ' + fmt(r.maxbytes, 0) + ' (relay fee ' + r.relayfee + ' quphi/kB)');
  if (!r.transactions.length) {
    setHtml('mp-body', '<tr><td colspan="5" class="dimmer">mempool empty</td></tr>');
    return;
  }
  setHtml('mp-body', r.transactions.map((t) => `<tr class="clickable" onclick="showTx('${t.txid}')">
    <td class="hash">${shortHash(t.txid)}</td>
    <td class="right">${t.inputs.length}</td>
    <td class="right">${t.outputs.length}</td>
    <td class="right dim">${fmt(t.size, 0)}</td>
    <td class="mono-sm">${t.outputs.map((o) => quh(o.value).replace(/0+$/, '') + ' → ' + shortAddr(o.address)).join('<br>')}</td>
  </tr>`).join(''));
}

async function showTx(txid) {
  try {
    const t = await api('/api/tx/' + txid);
    $('mp-detail').textContent = pretty(t);
  } catch (e) { toast('tx: ' + e.message, true); }
}

/* ------------------------------------------------------------------ wallet */
async function loadWallet() {
  await poll();
  const w = (state.status && state.status.wallet) || {};
  setText('w-path', w.path || '—');
  setText('w-exists', w.exists ? 'yes' : 'no');
  setText('w-net', w.network || '—');
  setText('w-cipher', w.cipher || '—');
  setText('w-kdf', w.kdf ? `${w.kdf} × ${fmt(w.kdf_iterations, 0)}` : '—');
  setText('w-next', w.next_index === undefined ? '—' : w.next_index);
  const count = parseInt($('w-count').value, 10) || 5;
  try {
    const r = await api('/api/wallet/addresses?count=' + count);
    if (!r.exists) {
      setHtml('w-addrs', '<tr><td colspan="5" class="dimmer">no wallet yet — press “Create wallet”</td></tr>');
    } else if (!r.addresses.length) {
      setHtml('w-addrs', '<tr><td colspan="5" class="warn">the wallet is sealed with a passphrase; use the Send / CLI panel to derive addresses</td></tr>');
    } else {
      setHtml('w-addrs', r.addresses.map((a) => `<tr class="clickable" onclick="document.getElementById('a-addr').value='${a.address}';showTab('wallet');document.getElementById('a-go').click()">
        <td class="dim">${a.index}</td>
        <td class="hash">${shortAddr(a.address)}</td>
        <td class="right">${a.balance_quh.toFixed(8)}</td>
        <td class="right ok">${a.matured_quh.toFixed(8)}</td>
        <td class="right dim">${a.nonce}</td></tr>`).join(''));
      if (!$('m-payout').value) $('m-payout').value = r.addresses[0].address;
      if (!$('s-to').value) $('s-to').value = r.addresses[0].address;
    }
  } catch (e) {
    setHtml('w-addrs', '<tr><td colspan="5" class="bad">' + esc(e.message) + '</td></tr>');
  }
}

async function walletCmd(args, outId) {
  const pass = $('w-pass').value;
  try {
    const r = await postJSON('/api/wallet', { args: args, passphrase: pass });
    setText(outId, (r.stdout || '') + (r.stderr || '') + (r.error ? ('\n' + r.error) : ''));
    if (r.ok) loadWallet();
    return r;
  } catch (e) { setText(outId, 'request failed: ' + e.message); }
}

/* ------------------------------------------------------------------- miner */
async function loadMiner() {
  await poll();
  renderMiner(state.status);
  try {
    const r = await postJSON('/api/rpc', { method: 'getmininginfo', params: {} });
    renderMinerInfo(r.result);
  } catch (e) { /* node may be read-only */ }
}

function renderMiner(s) {
  if (!s) return;
  setText('m-hash', fmt(s.hashrate, 0));
  setText('m-blocks', s.blocks_mined);
  setText('m-rejected', (s.blocks_rejected || 0) + ' rejected');
  setText('m-eta', s.mining ? '…' : 'idle');
  setText('mc-net', s.network + ' (' + s.hrp + ')');
  setText('mc-diff', s.difficulty < 1 ? s.difficulty.toExponential(3) : fmt(s.difficulty, 3));
  setText('mc-bits', s.bits);
  const warn = $('m-warn');
  if (warn) {
    warn.textContent = s.mining_allowed
      ? 'Solo mining is enabled on this network. The reference miner is pure Python: about 0.3 MH/s per core, because double SHA3-512 dominates. Correct and convenient for regtest — real mainnet hashrate needs a native SHA3-512 kernel.'
      : 'Solo mining is disabled on mainnet by this UI. Use `qeuph node --network mainnet --mine quh1…` from a terminal if you really want to.';
  }
  $('m-start').disabled = !s.mining_allowed;
}

function renderMinerInfo(m) {
  if (!m) return;
  if (m.target) setText('mc-target', parseInt(m.target, 16).toLocaleString());
  if (m.seconds_per_block_estimate) setText('mc-eta', fmt(m.seconds_per_block_estimate, 0) + ' s');
  const diff = m.network_difficulty || 1;
  const hr = (m.hashrate || 0);
  setText('mc-share', hr > 0 ? ((100 / diff) * (hr / (parseInt(m.target || '0x0', 16) || 1)) * 100).toExponential(3) + ' %' : '—');
  setText('m-eta', m.seconds_per_block_estimate ? fmt(m.seconds_per_block_estimate, 0) + ' s' : 'idle');
}

/* ---------------------------------------------------------------- emission */
async function loadEmission() {
  const e = await api('/api/emission');
  const cap = 31.5e6;
  setHtml('em-body', e.table.map((r) => `<tr>
    <td class="accent">${r.epoch}</td>
    <td class="right dim">${fmt(r.start_height, 0)}</td>
    <td class="right">${r.reward_quh.toFixed(8)}</td>
    <td class="right">${fmt(r.cumulative_quh, 3)}</td>
    <td><div class="bar" style="width:120px"><i style="width:${Math.min(100, (r.cumulative_quh / cap) * 100).toFixed(4)}%"></i></div></td>
  </tr>`).join(''));
}

/* ------------------------------------------------------------------ crypto */
async function loadCrypto() {
  const c = await api('/api/crypto');
  setHtml('c-params', Object.entries(c).map(([k, v]) =>
    `<dt>${esc(k.replace(/_/g, ' '))}</dt><dd>${esc(v)}</dd>`).join(''));
}

async function runCryptoTest() {
  const out = $('c-out');
  out.textContent = 'signing …';
  try {
    const r = await postJSON('/api/crypto/test', { message: $('c-msg').value });
    out.textContent = pretty(r);
  } catch (e) { out.textContent = 'failed: ' + e.message; }
}

/* ----------------------------------------------------------------- console */
const CLI_PRESETS = [
  'version', 'genesis', 'emission', 'chain info', 'chain blocks --limit 5',
  'chain verify', 'chain reindex', 'address validate quh1…', 'crypto info',
  'crypto test', 'rpc getblockchaininfo', 'rpc getnetworkinfo',
  'rpc getblocktemplate', 'rpc getmininginfo', 'rpc getmempoolinfo',
  'rpc help',
];
const WALLET_PRESETS = [
  'wallet create', 'wallet show --count 5', 'wallet balance',
  'wallet address --index 1', 'wallet newaddress', 'wallet utxos',
  'wallet send --to quh1… --amount 1 --fee 0.01', 'wallet sweep --to quh1…',
  'wallet backup', 'wallet verify --file tx.hex', 'wallet sign --file tx.hex',
];
const RPC_PRESETS = [
  'getblockchaininfo', 'getnetworkinfo', 'getbestblockhash', 'getblockcount',
  'getdifficulty', 'getmininginfo', 'getmempoolinfo', 'getrawmempool',
  'getblocktemplate', 'getpeerinfo', 'getrewardinfo', 'getblock', 'gettransaction',
  'getblockstats', 'getchaintips', 'getnodeinfo', 'help',
];

async function loadConsole() {
  const fill = (id, list) => {
    const s = $(id);
    s.innerHTML = list.map((x) => `<option value="${esc(x)}">${esc(x)}</option>`).join('');
    s.addEventListener('change', () => {
      if (id === 'cli-preset' || id === 'rpc-preset') $('cli-args').value = s.value;
    });
  };
  fill('cli-preset', CLI_PRESETS);
  const wrap = $('cli-preset').parentElement;
  wrap.innerHTML = '<label class="lbl" for="cli-preset">presets</label>';
  wrap.appendChild($('cli-preset'));
  fill('rpc-preset', RPC_PRESETS);
  try {
    const tree = await api('/api/cli');
    $('cli-tree').textContent = pretty(tree);
  } catch (e) { $('cli-tree').textContent = 'failed: ' + e.message; }
}

async function runCli(wallet) {
  const argv = $('cli-args').value.trim().split(/\s+/).filter(Boolean);
  if (!argv.length) return;
  const out = $('cli-out');
  out.textContent = 'running qeuph ' + argv.join(' ') + ' …';
  try {
    const body = { args: argv };
    if (wallet) body.passphrase = $('cli-pass').value;
    const r = await postJSON(wallet ? '/api/wallet' : '/api/cli', body);
    out.textContent = `$ qeuph ${r.args.join(' ')}\n` + (r.stdout || '') +
      (r.stderr ? '\n[stderr] ' + r.stderr : '') + (r.error ? '\n[error] ' + r.error : '') +
      `\n[exit ${r.exit_code}]`;
    if (state.tab === 'wallet') loadWallet();
  } catch (e) { out.textContent = 'failed: ' + e.message; }
}

async function runRpc() {
  const out = $('rpc-out');
  let params;
  try { params = JSON.parse($('rpc-params').value || '{}'); }
  catch (e) { out.textContent = 'params must be JSON: ' + e.message; return; }
  out.textContent = 'calling ' + $('rpc-method').value + ' …';
  try {
    const r = await postJSON('/api/rpc', { method: $('rpc-method').value, params: params, id: 1 });
    out.textContent = pretty(r);
  } catch (e) { out.textContent = 'failed: ' + e.message; }
}

/* ------------------------------------------------------------------- about */
async function loadAbout() {
  await poll();
  const s = state.status || {};
  const C = { QUH: 100000000, MAX: 31500000, RI: 2048, BT: 300, CM: 100, MF: 210000 };
  setHtml('ab-params', [
    ['block time', C.BT + ' s (5 minutes)'],
    ['retarget interval', fmt(C.RI, 0) + ' blocks (~7.1 days)'],
    ['retarget clamp', '×/÷ 4'],
    ['max block size', '2,000,000 B'],
    ['coinbase maturity', C.CM + ' blocks'],
    ['reward interval', fmt(C.MF, 0) + ' blocks (~2 years)'],
    ['initial reward', '50 QUH, ×2/3 per epoch'],
    ['supply cap', '31,500,000 QUH'],
    ['decimals', '8 (1 QUH = 100,000,000 quphi)'],
    ['dust threshold', '1,000 quphi'],
    ['relay fee', '1,000 quphi / kB'],
    ['signatures', 'ML-DSA-87 (FIPS 204), 4,627 B'],
    ['addresses', 'Bech32m (BIP-350), 512-bit digest, ' + s.hrp + '1…'],
    ['address length', '113 characters'],
    ['hashing', 'double SHA3-512 (FIPS 202)'],
    ['P2P / RPC ports', '19090 / 19091 (mainnet)'],
  ].map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join(''));
  setText('ab-version', s.version || '—');
  setText('ab-backend', s.backend || '—');
}

/* -------------------------------------------------------------------- wire */
function wire() {
  wireTabs();
  $('netpick').addEventListener('change', async (ev) => {
    const name = ev.target.value;
    if (!confirm('Switch the embedded node to ' + name + '? The current chain stays on disk and mining is stopped.')) {
      ev.target.value = state.status ? state.status.network : 'regtest';
      return;
    }
    try {
      await postJSON('/api/network', { network: name });
      showTab('dashboard');
    } catch (e) { alert('switch failed: ' + e.message); }
  });

  $('blocks-refresh').addEventListener('click', loadBlocks);
  $('blocks-limit').addEventListener('change', loadBlocks);
  $('blocks-gen').addEventListener('click', async () => {
    const r = await postJSON('/api/generate', { count: 1 });
    loadBlocks();
    poll();
  });
  $('mp-refresh').addEventListener('click', loadMempool);

  $('w-create').addEventListener('click', () => {
    const pass = $('w-pass').value;
    walletCmd(pass ? ['wallet', 'create'] : ['wallet', 'create', '--unencrypted'], 'w-out');
  });
  $('w-refresh').addEventListener('click', loadWallet);
  $('w-count').addEventListener('change', loadWallet);
  $('s-send').addEventListener('click', async () => {
    const argv = ['wallet', 'send', '--to', $('s-to').value.trim(),
      '--amount', $('s-amt').value, '--fee', $('s-fee').value,
      '--index', $('s-idx').value];
    const r = await walletCmd(argv, 's-out');
    if (r && r.ok) loadMempool();
  });
  $('a-go').addEventListener('click', async () => {
    const out = $('a-out');
    out.textContent = 'looking up …';
    try {
      out.textContent = pretty(await api('/api/address/' + encodeURIComponent($('a-addr').value.trim())));
    } catch (e) { out.textContent = 'failed: ' + e.message; }
  });

  $('m-start').addEventListener('click', async () => {
    const body = { threads: parseInt($('m-threads').value, 10) || 1 };
    if ($('m-payout').value.trim()) body.payout = $('m-payout').value.trim();
    try { await postJSON('/api/miner/start', body); loadMiner(); }
    catch (e) { alert('miner: ' + e.message); }
  });
  $('m-stop').addEventListener('click', async () => {
    await postJSON('/api/miner/stop', {}); loadMiner();
  });
  $('m-apply').addEventListener('click', async () => {
    await postJSON('/api/miner/threads', { threads: parseInt($('m-threads').value, 10) || 1 });
    loadMiner();
  });

  $('c-run').addEventListener('click', runCryptoTest);

  $('cli-run').addEventListener('click', () => runCli(false));
  $('cli-wallet').addEventListener('click', () => runCli(true));
  $('cli-args').addEventListener('keydown', (e) => { if (e.key === 'Enter') runCli($('cli-pass').value !== undefined && false); });
  $('rpc-run').addEventListener('click', runRpc);
  $('rpc-params').addEventListener('keydown', (e) => { if (e.key === 'Enter') runRpc(); });
}

document.addEventListener('DOMContentLoaded', () => {
  wire();
  poll().then(() => showTab('dashboard'));
  setInterval(poll, 3000);
});
