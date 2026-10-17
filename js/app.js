(function(){
'use strict';

var __loadMsg = null;
try {
  if (!window.crypto || !window.crypto.subtle) {
    if (location.protocol === 'data:') {
      __loadMsg = '当前以 data: URL 方式预览，浏览器在此环境下禁止使用 WebCrypto 加密 API，导致加密库无法加载。请将 index.html 保存为本地文件后双击打开（file://），或通过本地服务器（http://localhost）访问。';
    } else {
      __loadMsg = '浏览器未提供 WebCrypto（crypto.subtle）API。请在安全上下文中打开本页：双击本地文件（file://）或通过 http://localhost 访问。';
    }
  } else if (!window.openpgp) {
    __loadMsg = 'OpenPGP 库未能加载。可能原因：页面被部分截断 / 修改 / 浏览器插件冲突。请重新获取完整的 index.html 文件。';
  }
} catch (e) {
  __loadMsg = '页面初始化出错：' + (e && e.message || e);
}
if (__loadMsg) {
  var __errs = (window.__opgErrors || []).map(function(s){ return '<div>' + String(s).replace(/[<>&]/g, function(c){ return {'<':'&lt;','>':'&gt;','&':'&amp;'}[c]; }) + '</div>'; }).join('');
  document.body.insertAdjacentHTML('afterbegin',
    '<div style="max-width:640px;margin:20px auto;padding:16px 18px;border:1px solid #C44E4E;border-radius:8px;background:#FDF2F2;color:#1C1C1C;font-size:13px;line-height:1.7">' +
      '<div style="font-weight:600;color:#C44E4E;margin-bottom:8px">加密库未能加载，功能不可用。</div>' +
      '<div>' + __loadMsg.replace(/[<>&]/g, function(c){ return {'<':'&lt;','>':'&gt;','&':'&amp;'}[c]; }) + '</div>' +
      (__errs ? '<div style="margin-top:10px;padding-top:8px;border-top:1px solid rgba(196,78,78,.3);font-family:Consolas,monospace;font-size:12px"><div style="font-weight:600;margin-bottom:4px">浏览器错误详情：</div>' + __errs + '</div>' : '') +
      '<div style="margin-top:8px">window.openpgp = ' + typeof window.openpgp + ' · crypto.subtle = ' + (window.crypto && window.crypto.subtle ? '可用' : '不可用') + '</div>' +
    '</div>');
  return;
}

const $ = id => document.getElementById(id);
const STORE_KEY = 'openpgp_keys_v1';

// localStorage 可能在 file:// 等受限环境下不可用，回退到内存存储。
let storageOk = true;
let memStore = {};
try {
  const t = '__opg_test__';
  localStorage.setItem(t, '1');
  localStorage.removeItem(t);
} catch {
  storageOk = false;
  memStore = {};
}
function readStore(key){
  if (storageOk) return localStorage.getItem(key);
  return memStore[key] || null;
}
function writeStore(key, val){
  if (storageOk) localStorage.setItem(key, val);
  else memStore[key] = val;
}

/* ══════════ 基础工具 ══════════ */

// 滚动条占位补偿：
// - 支持 scrollbar-gutter: stable 的环境已预留空间（无可见缺口、无位移），
//   但预留量不反映在 clientWidth 中；
// - 不支持的环境（如自定义滚动条下的 Chromium）滚动条会挤压布局宽度。
// 两种情况下，「innerWidth - body.clientWidth」都等于滚动条实际挤占的
// 布局宽度（gutter 预留时恒为预留值），补偿到 body 左内边距后，
// 居中内容在滚动条出现/消失时始终相对视口居中、零位移。
function syncScrollbarPad(){
  const pad = Math.max(0, window.innerWidth - document.body.clientWidth);
  document.documentElement.style.setProperty('--sb-w', pad + 'px');
}

function esc(s){ return String(s==null?'':s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function pad(n){ return String(n).padStart(2,'0'); }
function fmtKeyID(hex){ return String(hex || '').replace(/(.{4})(?=.)/g, '$1 '); }
function fmtDate(d){
  if (d === null || d === undefined) return '—';
  if (d === Infinity) return '永不过期';
  return d.getFullYear() + '-' + pad(d.getMonth()+1) + '-' + pad(d.getDate());
}
function parseUserID(str){
  if (!str) return { name:'', email:'' };
  const m = String(str).match(/^(.*?)\s*<([^>]+)>$/);
  if (m) return { name: m[1].trim(), email: m[2].trim() };
  return { name: String(str).trim(), email: '' };
}
function userIDLabel(rec){
  if (rec.name && rec.email) return rec.name + ' <' + rec.email + '>';
  if (rec.name) return rec.name;
  if (rec.email) return rec.email;
  return '未命名';
}
function friendlyError(msg){
  if (!msg) return '未知错误';
  if (/passphrase|wrong secret key|Bad session key|Incorrect session key|Invalid session key|decryption failed/i.test(msg))
    return '密码或私钥口令不正确';
  if (/Could not find|No key|no key|unrecognised|unrecognized|Unknown packet|not a valid/i.test(msg))
    return '找不到匹配的密钥或无法解析输入内容';
  if (/armor|Armor/i.test(msg)) return '无法解析 ASCII armor 内容';
  if (/expired/i.test(msg)) return '密钥已过期';
  return msg;
}

/* ══════════ 密钥存储 ══════════ */

let keys = [];
const sessionKeys = new Map(); // fingerprint -> decrypted PrivateKey

function loadKeys(){
  try {
    const raw = readStore(STORE_KEY);
    keys = raw ? (JSON.parse(raw).keys || []) : [];
  } catch { keys = []; }
}
function saveKeys(){
  writeStore(STORE_KEY, JSON.stringify({ version: 1, keys }));
}
function getRec(fp){ return keys.find(k => k.fingerprint === fp); }

/* ══════════ 算法配置 ══════════ */

const CURVE_ECC = [
  { id:'curve25519', label:'Curve25519' },
  { id:'curve448',   label:'Curve448', v6Only: true },
  { id:'nistp256',   label:'NIST P-256' },
  { id:'nistp384',   label:'NIST P-384' },
  { id:'nistp521',   label:'NIST P-521' },
  { id:'brainpoolP256r1', label:'Brainpool P256r1' },
  { id:'brainpoolP384r1', label:'Brainpool P384r1' },
  { id:'brainpoolP512r1', label:'Brainpool P512r1' },
];
const RSA_ALGOS = [
  { id:'rsa2048', label:'RSA 2048' },
  { id:'rsa3072', label:'RSA 3072' },
  { id:'rsa4096', label:'RSA 4096' },
];

function keyGenOptions(algoId, keyVersion){
  const v6 = keyVersion === 'v6';
  const config = { v6Keys: v6 };
  if (algoId.indexOf('rsa') === 0)
    return { type:'rsa', rsaBits: parseInt(algoId.slice(3), 10), config };
  if (algoId === 'curve25519')
    return v6 ? { type:'curve25519', config } : { type:'ecc', curve:'curve25519Legacy', config };
  if (algoId === 'curve448')
    return { type:'curve448', config };
  const map = { nistp256:'nistP256', nistp384:'nistP384', nistp521:'nistP521',
    brainpoolP256r1:'brainpoolP256r1', brainpoolP384r1:'brainpoolP384r1', brainpoolP512r1:'brainpoolP512r1' };
  return { type:'ecc', curve: map[algoId], config };
}

const CURVE_NAMES = { nistP256:'NIST P-256', nistP384:'NIST P-384', nistP521:'NIST P-521',
  curve25519Legacy:'Curve25519', ed25519Legacy:'Curve25519',
  brainpoolP256r1:'Brainpool P256r1', brainpoolP384r1:'Brainpool P384r1', brainpoolP512r1:'Brainpool P512r1', secp256k1:'secp256k1' };
const ALGO_NAMES = { ecdsa:'ECDSA', eddsaLegacy:'EdDSA', ed25519:'EdDSA', ed448:'EdDSA',
  ecdh:'ECDH', x25519:'X25519', x448:'X448',
  rsaEncryptSign:'RSA', rsaSign:'RSA', rsaEncrypt:'RSA' };

function algoLabel(info){
  if (!info) return '—';
  const base = ALGO_NAMES[info.algorithm] || info.algorithm || '—';
  if (info.bits) return base + ' ' + info.bits + ' 位';
  if (info.curve) return base + '（' + (CURVE_NAMES[info.curve] || info.curve) + '）';
  return base;
}

function decodeFlags(flags){
  if (!flags || !flags.length) return '—';
  const f = flags[0];
  const out = [];
  if (f & 1) out.push('认证');
  if (f & 2) out.push('签名');
  if (f & 4) out.push('加密');
  if (f & 8) out.push('加密');
  if (f & 32) out.push('认证');
  if (!out.length) return '—';
  return Array.from(new Set(out)).join('、');
}

function inferUsage(info, isPrimary){
  if (!info) return '—';
  const alg = info.algorithm;
  if (alg === 'rsaEncryptSign') return isPrimary ? '签名' : '签名、加密';
  const enc = ['ecdh', 'x25519', 'x448'].indexOf(alg) >= 0;
  const sig = ['eddsaLegacy', 'ed25519', 'ed448', 'ecdsa'].indexOf(alg) >= 0;
  if (enc && sig) return '签名、加密';
  if (enc) return '加密';
  if (sig) return '签名';
  return '—';
}

/* ══════════ 密钥状态 ══════════ */

async function getKeyStatus(parsed){
  try {
    const revoked = await parsed.isRevoked();
    if (revoked) return { label:'已撤销', cls:'revoked' };
  } catch {}
  try {
    const exp = await parsed.getExpirationTime();
    if (exp !== null && exp !== Infinity && exp instanceof Date && exp < new Date())
      return { label:'已过期', cls:'expired' };
  } catch {}
  return { label:'有效', cls:'valid' };
}

/* ══════════ 界面基础 · 弹窗与提示 ══════════ */

async function copyText(text){
  try {
    await navigator.clipboard.writeText(text);
    toast('已复制');
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); toast('已复制'); } catch { toast('复制失败'); }
    document.body.removeChild(ta);
  }
}

/* ── 弹窗：被按下的那个按钮决定弹窗从哪儿长出来 ── */
function openModal(id, trigger){
  const ov = $(id);
  ov.classList.add('open');
  // 弹窗从被按下的那个按钮长出来（onetake morphRect：被按下的那个变成结果）。
  // 必须在回流之前设好，动画第一帧才用得上这个 origin。
  const modal = ov.querySelector('.modal');
  const trig = trigger || lastPressed;
  if (modal && trig && trig.getBoundingClientRect().width) {
    const t = trig.getBoundingClientRect(), m = modal.getBoundingClientRect();
    modal.style.setProperty('--ox', (t.left + t.width / 2 - m.left).toFixed(1) + 'px');
    modal.style.setProperty('--oy', (t.top + t.height / 2 - m.top).toFixed(1) + 'px');
  }
  // 打开后聚焦第一个可见的可交互元素（优先表单输入框），方便键盘操作
  const els = ov.querySelectorAll('input, select, textarea, button');
  let target = null;
  for (const wantField of [true, false]) {
    for (const el of els) {
      if (el.disabled || el.type === 'hidden' || !el.getClientRects().length) continue;
      if (wantField !== (el.tagName !== 'BUTTON')) continue;
      target = el; break;
    }
    if (target) break;
  }
  if (target) setTimeout(() => target.focus(), 10);
}
function closeModal(id){ $(id).classList.remove('open'); }

/* ── 提示（Snackbar）── */
let toastTimer = null;
function toast(msg){
  const t = $('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 2200);
}

/* ── 口令：prompt → 解密 ── */

let passResolver = null;
function promptPassphrase(rec){
  $('passLabel').textContent = '密钥「' + userIDLabel(rec) + '」受密码保护，请输入密码以继续。';
  $('passInput').value = '';
  resetPwToggle('passInput');
  openModal('modalPass');
  setTimeout(() => $('passInput').focus(), 30);
  return new Promise(resolve => { passResolver = resolve; });
}
function resolvePass(value){
  closeModal('modalPass');
  if (passResolver) { const r = passResolver; passResolver = null; r(value); }
}

async function getDecryptedPrivate(fp){
  if (sessionKeys.has(fp)) return sessionKeys.get(fp);
  const rec = getRec(fp);
  if (!rec || !rec.hasPrivate) throw new Error('没有可用私钥');
  let priv = await openpgp.readPrivateKey({ armoredKey: rec.privateArmored });
  if (rec.hasPassphrase) {
    const pass = await promptPassphrase(rec);
    if (pass === null) throw new Error('已取消');
    priv = await openpgp.decryptKey({ privateKey: priv, passphrase: pass });
  }
  sessionKeys.set(fp, priv);
  return priv;
}

/* ── 确认 ── */

let confirmResolver = null;
function confirmDialog(msg, yesText){
  $('confirmMsg').textContent = msg;
  $('confirmYes').textContent = yesText || '删除';
  openModal('modalConfirm');
  return new Promise(resolve => { confirmResolver = resolve; });
}
function resolveConfirm(value){
  closeModal('modalConfirm');
  if (confirmResolver) { const r = confirmResolver; confirmResolver = null; r(value); }
}

/* ══════════ 界面基础 · 动效 ══════════
   思想来自 onetake：位移是纯函数、曲线按动作性质选；看不见「因」的动效等于屏保。
   这里只放 CSS 做不到的三件事——重播、带 origin 的弹窗、跨边界的 carry。 */

// 重放一次性的入场动画：摘掉类 → 强制回流 → 再挂上，否则第二次同样的结果不会重播
function replay(el, cls){
  el.classList.remove(cls);
  void el.offsetWidth;
  el.classList.add(cls);
}

/* ── Tab 切换：指示器是唯一跨过边界的元素 ──
   旧做法是三块面板 display:none 互斥 + 同一个 6px 淡入，onetake 把这种判为 slideshow
   （「Mutually exclusive scenes are slides even with perfect rhythm」）。
   现在：胶囊滑过去并全程可见（carry），旧面板停在原地收走、新面板在 80ms 时开始上升，
   两者重叠 60ms —— 场景是交接的，不是替换的。 */
const TAB_RISE_MS = 700;      // var(--rise-handoff) + var(--dur-rise) + 最大错峰，之后摘掉 .rising

function placeTabIndicator(tab){
  const ind = $('tabIndicator');
  if (!ind || !tab) return;
  ind.style.width = tab.offsetWidth + 'px';
  ind.style.transform = 'translateX(' + tab.offsetLeft + 'px)';
}

function initTabIndicator(){
  const ind = $('tabIndicator');
  if (!ind) return;
  const place = () => placeTabIndicator(document.querySelector('.tab.active'));
  ind.classList.add('settled');            // 首帧直接落位，不播一段无意义的滑行
  place();
  void ind.offsetWidth;
  ind.classList.remove('settled');
  // 等字体到位、或者窗口/滚动条变化后宽度会变，指示器要跟着重新落位
  if (window.ResizeObserver) new ResizeObserver(place).observe(document.querySelector('.tabs'));
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(place);
}

function switchTab(tab){
  if (tab.classList.contains('active')) return;
  const from = document.querySelector('.tab-panel.active');
  const next = $('tab-' + tab.dataset.tab);

  // 旧面板就地固定成一份快照再收走：它不再占高度，新面板的位置就不会被它顶下去
  if (from) {
    const r = from.getBoundingClientRect();
    const ghost = from.cloneNode(true);
    ghost.removeAttribute('id');
    ghost.querySelectorAll('[id]').forEach(el => el.removeAttribute('id'));   // 不留重复 id
    ghost.querySelectorAll('label[for]').forEach(el => el.removeAttribute('for'));
    ghost.classList.remove('active', 'rising');
    ghost.classList.add('leaving');
    Object.assign(ghost.style, {
      position: 'fixed', left: r.left + 'px', top: r.top + 'px',
      width: r.width + 'px', margin: '0', zIndex: '5', overflow: 'hidden'
    });
    document.body.appendChild(ghost);
    const drop = () => ghost.remove();
    ghost.addEventListener('animationend', e => { if (e.animationName === 'panelLeave') drop(); });
    setTimeout(drop, 600);   // 兜底：万一动画没跑起来，别把快照留在页面上
    from.classList.remove('active');
  }

  if (next) {
    next.classList.add('active');
    // 立刻挂上，延迟由 CSS 的 --rise-handoff 承担 —— 挂晚了新内容会先整个显形再往下掉
    next.classList.add('rising');
    setTimeout(() => next.classList.remove('rising'), TAB_RISE_MS);
  }

  document.querySelectorAll('.tab').forEach(t => {
    t.classList.toggle('active', t === tab);
    t.setAttribute('aria-selected', t === tab ? 'true' : 'false');
  });
  placeTabIndicator(tab);
}

/* ── 接触反馈 ──
   按下有深度（:active 下压），松开弹出一圈环（onetake impact）。
   同时记住最后被按下的按钮：弹窗据此决定从哪儿长出来，不必逐处传参。 */
let lastPressed = null;
let suppressReveal = false;

function wireMotion(){
  const RING = '.btn, .btn-generate, .icon-btn, .file-pick, .btn-copy';
  let downRing = null;

  document.addEventListener('pointerdown', e => {
    const t = e.target;
    lastPressed = (t.closest && t.closest('button')) || null;
    downRing = (t.closest && t.closest(RING)) || null;
  }, true);

  document.addEventListener('pointerup', e => {
    const el = downRing; downRing = null;
    if (!el || !el.isConnected || el.disabled) return;
    if (!el.contains(e.target)) return;      // 按下后拖出去再松手，不算按到了它
    replay(el, 'impact');
  }, true);

  // 键盘触发的点击没有 pointerdown/up（detail 为 0）：补上环，并把「因」记成这个按钮
  document.addEventListener('click', e => {
    if (e.detail !== 0) return;
    const el = e.target.closest && e.target.closest(RING);
    if (!el || el.disabled) return;
    lastPressed = e.target.closest('button') || lastPressed;
    replay(el, 'impact');
  }, true);
}

/* ══════════ 界面渲染 ══════════ */

function renderNotepadSelects(){
  const prev = {};
  ['npSign', 'npForMe', 'npForOther'].forEach(id => { prev[id] = $(id).value; });
  const opts = [['', '无']].concat(keys.map(k => [k.fingerprint, userIDLabel(k)]));
  ['npSign', 'npForMe', 'npForOther'].forEach(id => {
    const el = $(id);
    el.innerHTML = '';
    opts.forEach(([v, l]) => {
      const o = document.createElement('option');
      o.value = v; o.textContent = l;
      el.appendChild(o);
    });
    if (id === 'npForOther') {
      const o = document.createElement('option');
      o.value = '__paste'; o.textContent = '粘贴对方公钥…';
      el.appendChild(o);
    }
    el.value = prev[id]; // 重建后恢复原选中项（已删除的密钥会自然回到「无」）
    if (el.selectedIndex === -1) el.selectedIndex = 0;
  });
}

async function renderKeys(){
  renderNotepadSelects();
  const empty = $('keysEmpty'), list = $('keysList');
  const hasKeys = keys.length > 0;
  // 没有密钥时收起工具栏 —— 空状态自带同样的两个按钮，摆两对只会显得别扭
  $('keysToolbar').classList.toggle('hidden', !hasKeys);
  empty.classList.toggle('hidden', hasKeys);
  list.classList.toggle('hidden', !hasKeys);
  if (!hasKeys) return;

  list.innerHTML = '';
  const statuses = await Promise.all(keys.map(rec =>
    openpgp.readKey({ armoredKey: rec.publicArmored })
      .then(k => getKeyStatus(k))
      .catch(() => ({ label:'有效', cls:'valid' }))
  ));
  keys.forEach((rec, i) => {
    const status = statuses[i];
    const nature = rec.hasPrivate ? '公私钥对' : '公钥';
    const card = document.createElement('div');
    card.className = 'key-card';
    card.innerHTML =
      '<div class="key-top">' +
        '<span class="key-name">' + esc(userIDLabel(rec)) + '</span>' +
        '<span class="badge badge-' + status.cls + '">' + status.label + ' · ' + nature + '</span>' +
      '</div>' +
      '<div class="key-meta">' +
        '<span class="mono">密钥 ID：' + esc(fmtKeyID(rec.keyID) || '—') + '</span>' +
      '</div>' +
      '<div class="key-actions">' +
        '<button class="btn btn-mini" data-act="pub">导出公钥</button>' +
        '<button class="btn btn-mini" data-act="sec"' + (rec.hasPrivate ? '' : ' disabled title="该密钥仅公钥，无私钥可导出"') + '>导出私钥</button>' +
        '<button class="btn btn-mini" data-act="detail">详细信息</button>' +
        '<button class="btn btn-mini btn-danger" data-act="del">删除</button>' +
      '</div>';
    card.querySelectorAll('button[data-act]').forEach(btn => {
      btn.addEventListener('click', () => {
        const act = btn.dataset.act;
        if (act === 'pub') exportPublic(rec);
        else if (act === 'sec') exportPrivate(rec);
        else if (act === 'detail') openDetail(rec.fingerprint);
        else if (act === 'del') deleteKey(rec.fingerprint);
      });
    });
    list.appendChild(card);
  });
}

/* ══════════ 创建密钥 ══════════ */

function buildAlgoSelect(){
  let html = '<optgroup label="ECC 椭圆曲线">';
  CURVE_ECC.forEach(a => {
    html += '<option value="' + a.id + '"' + (a.id === 'curve25519' ? ' selected' : '') + '>' + a.label + '</option>';
  });
  html += '</optgroup><optgroup label="RSA">';
  RSA_ALGOS.forEach(a => { html += '<option value="' + a.id + '">' + a.label + '</option>'; });
  html += '</optgroup>';
  $('algoSelect').innerHTML = html;
  syncAlgoAvailability();
}

function syncAlgoAvailability(){
  const opt = $('algoSelect').querySelector('option[value="curve448"]');
  if (opt) opt.disabled = $('fmtSelect').value === 'v4';
  // 切换到 v4 时若正选中仅 v6 支持的 Curve448，重置为 Curve25519，避免提交无效组合
  if (opt && opt.disabled && $('algoSelect').value === 'curve448') $('algoSelect').value = 'curve25519';
}

function setCreateLoading(loading){
  $('btnSubmitCreate').disabled = loading;
  $('btnSubmitCreate').textContent = loading ? '正在生成密钥…' : '创建';
  ['cName','cEmail','cPassword','algoSelect','cExpiry','cNeverExpire','fmtSelect'].forEach(id => $(id).disabled = loading);
}

async function submitCreate(){
  const name = $('cName').value.trim();
  const email = $('cEmail').value.trim();
  const errEl = $('cErr');
  errEl.classList.remove('visible');
  if (!name && !email) { errEl.textContent = '名称和邮箱至少填写一个。'; errEl.classList.add('visible'); return; }

  const pass = $('cPassword').value;
  const algo = $('algoSelect').value;
  const fmt = $('fmtSelect').value;
  const never = $('cNeverExpire').checked;

  let seconds = 0;
  if (!never) {
    const exp = new Date($('cExpiry').value + 'T23:59:59');
    if (isNaN(exp.getTime())) { errEl.textContent = '请选择有效期至的日期。'; errEl.classList.add('visible'); return; }
    const diff = Math.round((exp.getTime() - Date.now()) / 1000);
    if (diff <= 0) { errEl.textContent = '有效期至不能早于当前时间。'; errEl.classList.add('visible'); return; }
    seconds = diff;
  }

  const uid = {};
  if (name) uid.name = name;
  if (email) uid.email = email;

  const opts = keyGenOptions(algo, fmt);
  opts.userIDs = [uid];
  if (pass) opts.passphrase = pass;
  opts.keyExpirationTime = seconds;
  opts.format = 'armored';

  setCreateLoading(true);
  try {
    const { privateKey, publicKey } = await openpgp.generateKey(opts);
    const parsed = await openpgp.readKey({ armoredKey: privateKey });
    const rec = {
      fingerprint: parsed.getFingerprint(),
      keyID: parsed.getKeyID().toHex(),
      name: name,
      email: email,
      privateArmored: privateKey,
      publicArmored: publicKey,
      hasPrivate: true,
      hasPassphrase: !!pass,
      keyVersion: fmt,
      createdAt: new Date().toISOString(),
    };
    keys.push(rec);
    saveKeys();
    closeModal('modalCreate');
    toast('密钥创建成功');
    renderKeys();
  } catch (e) {
    errEl.textContent = friendlyError(e && e.message);
    errEl.classList.add('visible');
  } finally {
    setCreateLoading(false);
  }
}

/* ══════════ 导入密钥 ══════════ */

let pendingImport = null;

function openImport(){
  pendingImport = null;
  $('impFile').value = '';
  $('impClip').value = '';
  $('impPreview').classList.add('hidden');
  $('impErr').classList.remove('visible');
  $('btnConfirmImport').disabled = true;
  switchImpTab('file');
  openModal('modalImport');
}

function switchImpTab(which){
  $('impFileTab').classList.toggle('active', which === 'file');
  $('impClipTab').classList.toggle('active', which === 'clip');
  $('impFileWrap').classList.toggle('hidden', which !== 'file');
  $('impClipWrap').classList.toggle('hidden', which !== 'clip');
}

async function readKeyFromFile(file){
  const text = await file.text();
  try {
    const parsed = await openpgp.readKey({ armoredKey: text });
    return { parsed, armored: text };
  } catch {
    const buf = await file.arrayBuffer();
    const parsed = await openpgp.readKey({ binaryKey: new Uint8Array(buf) });
    return { parsed, armored: parsed.armor() };
  }
}

async function previewParsed(parsed, armored){
  try {
    const fp = parsed.getFingerprint();
    if (keys.some(k => k.fingerprint === fp)) {
      $('impErr').textContent = '该密钥已存在，无需重复导入。';
      $('impErr').classList.add('visible');
      $('btnConfirmImport').disabled = true;
      return;
    }
    pendingImport = { parsed, armored };
    $('impErr').classList.remove('visible');
    $('impPreview').innerHTML =
      '<div class="imp-line"><span>用户ID</span><b>' + esc(parsed.getUserIDs()[0] || '（无）') + '</b></div>' +
      '<div class="imp-line"><span>指纹</span><b class="mono">' + esc(fp) + '</b></div>' +
      '<div class="imp-line"><span>类型</span><b>' + (parsed.isPrivate() ? '私钥（含私钥材料）' : '公钥') + '</b></div>' +
      '<div class="imp-line"><span>格式</span><b>OpenPGP ' + esc(String(parsed.keyPacket.version)) + ' 版</b></div>';
    $('impPreview').classList.remove('hidden');
    $('btnConfirmImport').disabled = false;
  } catch (e) {
    $('impErr').textContent = friendlyError(e && e.message);
    $('impErr').classList.add('visible');
    $('btnConfirmImport').disabled = true;
  }
}

async function confirmImport(){
  if (!pendingImport) return;
  const { parsed, armored } = pendingImport;
  try {
    const fp = parsed.getFingerprint();
    const { name, email } = parseUserID(parsed.getUserIDs()[0] || '');
    let privateArmored = null, hasPrivate = false, hasPassphrase = false;
    if (parsed.isPrivate()) {
      hasPrivate = true;
      privateArmored = armored;
      try {
        const priv = await openpgp.readPrivateKey({ armoredKey: armored });
        hasPassphrase = !priv.getKeys().every(kk => kk.keyPacket.isDecrypted());
      } catch {}
    }
    const publicArmored = parsed.toPublic().armor();
    const ver = parsed.keyPacket.version;
    keys.push({
      fingerprint: fp,
      keyID: parsed.getKeyID().toHex(),
      name: name,
      email: email,
      privateArmored: privateArmored,
      publicArmored: publicArmored,
      hasPrivate: hasPrivate,
      hasPassphrase: hasPassphrase,
      keyVersion: ver === 6 ? 'v6' : (ver === 4 ? 'v4' : 'v' + ver),
      createdAt: new Date().toISOString(),
    });
    saveKeys();
    closeModal('modalImport');
    pendingImport = null;
    toast('密钥导入成功');
    renderKeys();
  } catch (e) {
    $('impErr').textContent = friendlyError(e && e.message);
    $('impErr').classList.add('visible');
  }
}

/* ══════════ 导出 / 删除 ══════════ */

function download(name, content, type){
  const blob = new Blob([content], { type: type || 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = name;
  document.body.appendChild(a); a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1000);
}

function safeName(rec){ return (rec.name || rec.keyID || 'key').replace(/[\\/:*?"<>|\s]+/g, '_').slice(0, 40); }

function exportPublic(rec){
  download(safeName(rec) + '-' + (rec.keyID || rec.fingerprint).slice(-8) + '.pub.asc', rec.publicArmored, 'application/pgp-keys');
}
function exportPrivate(rec){
  if (!rec.hasPrivate) { toast('该密钥没有私钥'); return; }
  download(safeName(rec) + '-' + (rec.keyID || rec.fingerprint).slice(-8) + '.sec.asc', rec.privateArmored, 'application/pgp-keys');
}

async function deleteKey(fp){
  const rec = getRec(fp);
  if (!rec) return;
  const ok = await confirmDialog('确定要删除密钥「' + userIDLabel(rec) + '」吗？\n此操作不可撤销，删除前请确认已导出私钥备份。');
  if (!ok) return;
  keys = keys.filter(k => k.fingerprint !== fp);
  sessionKeys.delete(fp);
  saveKeys();
  renderKeys();
  toast('密钥已删除');
}

/* ══════════ 详细信息 ══════════ */

async function openDetail(fp){
  const rec = getRec(fp);
  if (!rec) return;
  openModal('modalDetail');
  $('detContent').innerHTML = '<div class="muted">加载中…</div>';
  try {
    const pub = await openpgp.readKey({ armoredKey: rec.publicArmored });
    const priv = rec.hasPrivate ? await openpgp.readPrivateKey({ armoredKey: rec.privateArmored }) : null;
    const status = await getKeyStatus(pub);
    const created = pub.getCreationTime();
    const exp = await pub.getExpirationTime().catch(() => null);

    const allKeys = pub.getKeys();
    const privAll = priv ? priv.getKeys() : null;

    let rowsHtml = '';
    for (let i = 0; i < allKeys.length; i++) {
      const k = allKeys[i];
      const isPrimary = i === 0;
      const expT = await k.getExpirationTime().catch(() => null);
      const algoInfo = k.getAlgorithmInfo();
      const algo = algoLabel(algoInfo);
      const flags = isPrimary ? null : (k.bindingSignatures && k.bindingSignatures[0] ? k.bindingSignatures[0].keyFlags : null);
      const usage = isPrimary ? inferUsage(algoInfo, true) : (decodeFlags(flags) || inferUsage(algoInfo, false));

      let st = { label:'有效', cls:'valid' };
      if (expT !== null && expT !== Infinity && expT instanceof Date && expT < new Date()) st = { label:'已过期', cls:'expired' };
      if (isPrimary && status.label === '已撤销') st = status;
      if (!isPrimary && k.revocationSignatures && k.revocationSignatures.length) st = { label:'已撤销', cls:'revoked' };

      rowsHtml += '<tr>' +
        '<td class="mono fp-cell">' + esc(k.getFingerprint()) + '</td>' +
        '<td><span class="badge badge-' + st.cls + '">' + st.label + '</span></td>' +
        '<td>' + fmtDate(k.getCreationTime()) + ' → ' + fmtDate(expT) + '</td>' +
        '<td>' + usage + '</td>' +
        '<td>' + algo + '</td>' +
      '</tr>';
    }

    const never = !(exp instanceof Date);
    $('detContent').innerHTML =
      '<div class="det-section">' +
        '<div class="det-label">用户ID</div>' +
        '<div class="det-value">' + esc(userIDLabel(rec)) + '</div>' +
      '</div>' +
      '<div class="det-section">' +
        '<div class="det-label">日期</div>' +
        '<div class="det-value">' +
          '<span id="detDates">' + fmtDate(created) + ' → ' + fmtDate(exp) + '</span>' +
          '<button class="icon-btn" id="btnEditExpiry" title="更改到期日期">' +
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
              '<path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>' +
              '<path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>' +
            '</svg>' +
          '</button>' +
        '</div>' +
        '<div id="detExpiryEdit" class="det-edit hidden">' +
          '<input type="date" id="detExpiryInput" value="' + (never ? '' : fmtDate(exp)) + '"' + (never ? ' disabled' : '') + '>' +
          '<label class="check-inline"><input type="checkbox" id="detNeverExpire"' + (never ? ' checked' : '') + '>永不过期</label>' +
          '<button class="btn btn-mini" id="btnSaveExpiry">保存</button>' +
          '<button class="btn btn-mini btn-ghost" id="btnCancelExpiry">取消</button>' +
        '</div>' +
      '</div>' +
      '<div class="det-section">' +
        '<div class="det-label">状态</div>' +
        '<div class="det-value"><span class="badge badge-' + status.cls + '">' + status.label + '</span></div>' +
      '</div>' +
      '<div class="det-section">' +
        '<div class="det-label">指纹</div>' +
        '<div class="det-value"><span class="mono fp-full">' + esc(pub.getFingerprint()) + '</span>' +
          '<button class="icon-btn" data-copy="' + esc(pub.getFingerprint()) + '" title="复制指纹">' +
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
              '<rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>' +
              '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>' +
            '</svg>' +
          '</button></div>' +
      '</div>' +
      '<div class="det-section">' +
        '<div class="det-label">私钥</div>' +
        '<div class="det-value">' +
          (rec.hasPrivate
            ? '<button class="btn btn-mini" id="btnShowPriv">显示私钥</button>' +
              '<button class="btn btn-mini" data-download="sec">下载私钥</button>'
            : '<span class="muted">无（仅公钥）</span>') +
        '</div>' +
        '<div id="detPrivBox" class="hidden"><textarea class="mono priv-box" readonly></textarea>' +
          '<div style="margin-top:6px"><button class="icon-btn" data-copy="" title="复制私钥">' +
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
              '<rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>' +
              '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>' +
            '</svg>' +
          '</button></div></div>' +
      '</div>' +
      '<div class="det-section">' +
        '<div class="det-label">子密钥信息</div>' +
        '<table class="det-table"><thead><tr>' +
          '<th>指纹</th><th>状态</th><th>日期</th><th>用途</th><th>算法</th>' +
        '</tr></thead><tbody>' + rowsHtml + '</tbody></table>' +
      '</div>';

    $('detContent').querySelectorAll('[data-copy]').forEach(b => {
      b.addEventListener('click', () => copyText(b.dataset.copy));
    });
    const showBtn = $('btnShowPriv');
    if (showBtn) {
      showBtn.addEventListener('click', () => {
        const box = $('detPrivBox');
        const ta = box.querySelector('textarea');
        const hidden = box.classList.contains('hidden');
        box.classList.toggle('hidden', !hidden);
        if (hidden) {
          ta.value = rec.privateArmored;
          const copyBtn = box.querySelector('[data-copy]');
          if (copyBtn) copyBtn.dataset.copy = rec.privateArmored;
        }
      });
    }
    const dlBtn = $('detContent').querySelector('[data-download="sec"]');
    if (dlBtn) dlBtn.addEventListener('click', () => exportPrivate(rec));

    $('btnEditExpiry').addEventListener('click', () => $('detExpiryEdit').classList.toggle('hidden'));
    $('btnCancelExpiry').addEventListener('click', () => $('detExpiryEdit').classList.add('hidden'));
    $('detNeverExpire').addEventListener('change', () => { $('detExpiryInput').disabled = $('detNeverExpire').checked; });
    $('btnSaveExpiry').addEventListener('click', async () => {
      const never = $('detNeverExpire').checked;
      let date = null;
      if (!never) {
        const v = $('detExpiryInput').value;
        if (!v) { toast('请选择日期'); return; }
        date = new Date(v + 'T23:59:59');
        if (date <= new Date()) { toast('到期日期不能早于当前时间'); return; }
      }
      try {
        await changeExpiry(rec, date);
        closeModal('modalDetail');
        toast('到期日期已更新');
        renderKeys();
      } catch (e) {
        toast('更新失败：' + friendlyError(e && e.message));
      }
    });
  } catch (e) {
    $('detContent').innerHTML = '<div class="muted">加载失败：' + esc(e && e.message) + '</div>';
  }
}

async function changeExpiry(rec, newExpiryDate){
  if (!rec.hasPrivate) throw new Error('该密钥没有私钥');
  let priv = await openpgp.readPrivateKey({ armoredKey: rec.privateArmored });
  let pass = '';
  if (rec.hasPassphrase) {
    pass = await promptPassphrase(rec);
    if (pass === null) throw new Error('已取消');
    priv = await openpgp.decryptKey({ privateKey: priv, passphrase: pass });
  }
  const creation = priv.getCreationTime();
  const seconds = newExpiryDate ? Math.max(0, Math.round((newExpiryDate.getTime() - creation.getTime()) / 1000)) : 0;
  const opts = { privateKey: priv, keyExpirationTime: seconds, date: creation, format: 'armored' };
  if (rec.hasPassphrase) opts.passphrase = pass;
  const { privateKey, publicKey } = await openpgp.reformatKey(opts);
  rec.privateArmored = privateKey;
  rec.publicArmored = publicKey;
  sessionKeys.delete(rec.fingerprint); // 清除旧的已解密缓存，下次使用时会重新读取
  saveKeys();
}

/* ══════════ 记事本操作 ══════════ */

function findKeyNameByKeyID(kid){
  for (const rec of keys) {
    if (rec.keyID === kid) return userIDLabel(rec);
  }
  return null;
}

function showResult(text, statusMsg, cls){
  const status = $('npStatus');
  if (statusMsg) {
    status.textContent = statusMsg;
    status.className = 'status-banner ' + (cls || 'ok');
    status.classList.remove('hidden');
    replay(status, 'reveal');
  } else {
    status.classList.add('hidden');
  }
  $('npOutput').value = text;
}
function showOpError(msg){
  const status = $('npStatus');
  status.textContent = msg;
  status.className = 'status-banner error';
  status.classList.remove('hidden');
  replay(status, 'reveal');   // 报错条和成功条走同样的入场，别一个滑一个跳
  toast(msg);
}

async function collectEncryptionKeys(){
  const encryptionKeys = [];
  const seen = new Set();
  const addKey = k => {
    const fp = k.getFingerprint();
    if (!seen.has(fp)) { seen.add(fp); encryptionKeys.push(k); }
  };
  const meFp = $('npForMe').value;
  const otherFp = $('npForOther').value;
  const otherPaste = $('npOtherKey').value.trim();
  if (meFp) {
    const rec = getRec(meFp);
    if (rec) addKey(await openpgp.readKey({ armoredKey: rec.publicArmored }));
  }
  if (otherFp && otherFp !== '__paste') {
    const rec = getRec(otherFp);
    if (rec) addKey(await openpgp.readKey({ armoredKey: rec.publicArmored }));
  }
  if (otherPaste) {
    const k = await openpgp.readKey({ armoredKey: otherPaste });
    addKey(k.toPublic());
  }
  return encryptionKeys;
}

async function getSigningPrivate(){
  const fp = $('npSign').value;
  if (!fp) return null;
  return await getDecryptedPrivate(fp);
}

async function doEncrypt(){
  const text = $('npInput').value;

  const signFp = $('npSign').value;
  const password = $('npPassword').value;
  const meFp = $('npForMe').value;
  const otherFp = $('npForOther').value;
  const otherPaste = $('npOtherKey').value.trim();
  const hasTarget = !!(meFp || (otherFp && otherFp !== '__paste') || otherPaste || password);
  if (!hasTarget && !signFp) { showOpError('请至少选择一项：签名为 / 为我加密 / 为他人加密 / 使用密码加密。'); return; }

  try {
    const message = await openpgp.createMessage({ text });
    const encryptionKeys = await collectEncryptionKeys();
    const passwords = password ? [password] : [];

    let signingKeys = [];
    if (signFp) signingKeys.push(await getDecryptedPrivate(signFp));

    if (encryptionKeys.length === 0 && passwords.length === 0) {
      const cleartext = await openpgp.createCleartextMessage({ text });
      const signed = await openpgp.sign({ message: cleartext, signingKeys });
      showResult(signed, '签名成功（仅签名，未加密）。', 'info');
      return;
    }

    const encOpts = { message, encryptionKeys, format: 'armored' };
    if (passwords.length) encOpts.passwords = passwords;
    if (signingKeys.length) encOpts.signingKeys = signingKeys;
    const armored = await openpgp.encrypt(encOpts);
    const via = [];
    if (encryptionKeys.length) via.push('密钥');
    if (passwords.length) via.push('密码');
    const signedMsg = signingKeys.length ? '，并已签名' : '';
    showResult(armored, '加密成功（使用' + via.join('+') + '）' + signedMsg + '。');
  } catch (e) {
    showOpError('加密失败：' + friendlyError(e && e.message));
  }
}

async function doSign(){
  const text = $('npInput').value;
  if (!text.trim()) { showOpError('请输入要签名的信息。'); return; }
  const fp = $('npSign').value;
  if (!fp) { showOpError('请先选择「签名为」的密钥。'); return; }
  try {
    const priv = await getDecryptedPrivate(fp);
    const cleartext = await openpgp.createCleartextMessage({ text });
    const signed = await openpgp.sign({ message: cleartext, signingKeys: [priv] });
    showResult(signed, '签名成功。');
  } catch (e) {
    showOpError('签名失败：' + friendlyError(e && e.message));
  }
}

async function describeSignatures(signatures){
  const parts = [];
  for (const sig of signatures || []) {
    const kid = sig.keyID.toHex();
    const owner = findKeyNameByKeyID(kid);
    try {
      await sig.verified;
      parts.push('签名验证成功：' + (owner || kid));
    } catch (e) {
      parts.push('签名验证失败：' + (owner || kid) + '（' + (e && e.message || '签名无效') + '）');
    }
  }
  return parts;
}

async function doDecrypt(){
  const armored = $('npInput').value.trim();
  if (!armored) { showOpError('请输入要解密的信息。'); return; }

  let msg;
  try {
    msg = await openpgp.readMessage({ armoredMessage: armored });
  } catch {
    try {
      await openpgp.readCleartextMessage({ cleartextMessage: armored });
      showOpError('这是清文本签名消息（未加密）。请使用「验证」按钮。');
    } catch {
      showOpError('无法解析输入内容：不是有效的 PGP 密文。');
    }
    return;
  }

  const password = $('npPassword').value;
  const passwords = password ? [password] : [];

  try {
    const targetKeyIDs = msg.getEncryptionKeyIDs().map(k => k.toHex());
    const decryptionKeys = [];
    let matched = null;
    if (targetKeyIDs.length) {
      for (const rec of keys) {
        if (!rec.hasPrivate) continue;
        const kp = await openpgp.readPrivateKey({ armoredKey: rec.privateArmored });
        const ids = kp.getKeys().map(kk => kk.getKeyID().toHex());
        if (targetKeyIDs.some(id => ids.indexOf(id) >= 0)) { matched = rec; break; }
      }
      if (matched) {
        decryptionKeys.push(await getDecryptedPrivate(matched.fingerprint));
      } else if (!passwords.length) {
        showOpError('没有找到能解密此消息的私钥。若消息使用密码加密，请先在上方输入密码。');
        return;
      }
    }
    if (!targetKeyIDs.length && !passwords.length) {
      showOpError('无法确定消息的解密对象（未指定收件人密钥 ID）。若消息使用密码加密，请先在上方输入密码。');
      return;
    }

    const verificationKeys = [];
    for (const rec of keys) {
      try { verificationKeys.push(await openpgp.readKey({ armoredKey: rec.publicArmored })); } catch {}
    }

    const decryptOpts = {
      message: msg,
      decryptionKeys: decryptionKeys,
      verificationKeys: verificationKeys,
      format: 'utf8',
    };
    if (passwords.length) decryptOpts.passwords = passwords;
    const { data, signatures } = await openpgp.decrypt(decryptOpts);

    const sigParts = await describeSignatures(signatures);
    let note = '解密成功';
    if (sigParts.length) note += '。' + sigParts.join('；');
    else if (passwords.length) note += '（使用密码解密，该消息未签名）。';
    else note += '。该消息未签名。';
    showResult(String(data), note);
  } catch (e) {
    showOpError('解密失败：' + friendlyError(e && e.message));
  }
}

async function doVerify(){
  const armored = $('npInput').value.trim();
  if (!armored) { showOpError('请输入要验证的消息。'); return; }
  if (!keys.length) { showOpError('请先创建或导入密钥，用于验证签名。'); return; }

  const verificationKeys = [];
  for (const rec of keys) {
    verificationKeys.push(await openpgp.readKey({ armoredKey: rec.publicArmored }));
  }

  try {
    let res = null;
    let text = null;
    try {
      const cl = await openpgp.readCleartextMessage({ cleartextMessage: armored });
      res = await openpgp.verify({ message: cl, verificationKeys });
      text = res.data;
    } catch (e1) {
      let msg;
      try {
        msg = await openpgp.readMessage({ armoredMessage: armored });
      } catch {
        showOpError('无法解析输入内容：不是有效的 PGP 签名消息。');
        return;
      }
      try {
        res = await openpgp.verify({ message: msg, verificationKeys });
        text = res.data;
      } catch (e2) {
        const targets = msg.getEncryptionKeyIDs();
        if (targets && targets.length) {
          showOpError('这是加密消息，请使用「解密」按钮。');
        } else {
          showOpError('该消息没有可验证的签名。');
        }
        return;
      }
    }
    const sigParts = await describeSignatures(res.signatures);
    if (!sigParts.length) { showOpError('该消息没有签名。'); return; }
    showResult(String(text), sigParts.join('；'));
  } catch (e) {
    showOpError('验证失败：' + friendlyError(e && e.message));
  }
}

/* ══════════ 密码生成 ══════════ */

const POOLS = {
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lower: 'abcdefghijklmnopqrstuvwxyz',
  digit: '0123456789',
  special: '!@#$%^*',
};
const AMBIGUOUS = '1lIo0';

function pwRemoveChars(str, chars) {
  const set = new Set(chars);
  return str.split('').filter(c => !set.has(c)).join('');
}
// 密码学安全随机数（crypto.getRandomValues），拒绝采样消除取模偏差；极端环境回退 Math.random
function pwRand(n) {
  const buf = new Uint32Array(1);
  if (window.crypto && crypto.getRandomValues) {
    const limit = Math.floor(0x100000000 / n) * n;
    let v;
    do { crypto.getRandomValues(buf); v = buf[0]; } while (v >= limit);
    return v % n;
  }
  return Math.floor(Math.random() * n);
}
function pwShuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = pwRand(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}
function pwPick(arr) { return arr[pwRand(arr.length)]; }
function pwPickN(arr, n) {
  if (n === 0) return [];
  const copy = arr.slice();
  pwShuffle(copy);
  return copy.slice(0, n);
}

function pwGetPools() {
  const ambiguous = $('optAmbiguous').checked;
  const pools = [];
  function addPool(key, checkedEl, minEl, fullSet) {
    if (!checkedEl.checked) return;
    let chars = fullSet;
    if (ambiguous) chars = pwRemoveChars(chars, AMBIGUOUS);
    const min = Math.max(0, parseInt(minEl.value, 10) || 0);
    pools.push({ key, chars, min });
  }
  addPool('upper', $('chkUpper'), $('minUpper'), POOLS.upper);
  addPool('lower', $('chkLower'), $('minLower'), POOLS.lower);
  addPool('digit', $('chkDigit'), $('minDigit'), POOLS.digit);
  addPool('special', $('chkSpecial'), $('minSpecial'), POOLS.special);
  return pools;
}

function pwGetCombinedPool(pools) {
  const set = new Set();
  for (const p of pools) for (const c of p.chars) set.add(c);
  return Array.from(set);
}

function pwValidate(length, pools) {
  if (pools.length === 0) return '请至少选择一种字符类型。';
  const totalMin = pools.reduce((s, p) => s + p.min, 0);
  if (totalMin > length) return `各类型最少字符数之和 (${totalMin}) 超过了密码长度 (${length})，请减少最少个数或增加密码长度。`;
  const names = { upper: '大写字母', lower: '小写字母', digit: '数字', special: '特殊符号' };
  for (const p of pools) {
    if (p.min > p.chars.length)
      return `"${names[p.key] || p.key}" 排除易混淆字符后可用字符不足 ${p.min} 个（仅剩 ${p.chars.length} 个），请减少该类型的最少个数。`;
  }
  if ($('optDuplicate').checked) {
    const combined = pwGetCombinedPool(pools);
    if (combined.length < length)
      return `"无重复字符" 模式下，可用字符集仅 ${combined.length} 个唯一字符，无法生成 ${length} 位无重复密码。请增加字符类型或减少密码长度。`;
  }
  return null;
}

function pwGenerate() {
  const length = parseInt($('pwLength').value, 10);
  const pools = pwGetPools();
  const err = pwValidate(length, pools);
  if (err) {
    $('errorMsg').textContent = err;
    $('errorMsg').classList.add('visible');
    $('passwordSection').classList.add('hidden');
    return;
  }
  $('errorMsg').classList.remove('visible');

  let password = [];
  for (const p of pools) {
    if (p.min > 0) password.push(...pwPickN(p.chars.split(''), p.min));
  }
  const remaining = length - password.length;
  if (remaining > 0) {
    if ($('optDuplicate').checked) {
      const used = new Set(password);
      const combined = pwGetCombinedPool(pools).filter(c => !used.has(c));
      password.push(...pwPickN(combined, remaining));
    } else {
      const combined = pwGetCombinedPool(pools);
      for (let i = 0; i < remaining; i++) password.push(pwPick(combined));
    }
  }
  pwShuffle(password);
  pwShowResult(password.join(''), length, pools);
}

function pwCalcStrength(password, pools) {
  const combined = pwGetCombinedPool(pools);
  const poolSize = combined.length;
  let entropy;
  if ($('optDuplicate').checked) {
    // 无重复字符（不放回抽样）：每个位置的可选字符数递减，熵按各位置求和
    entropy = 0;
    for (let i = 0; i < password.length; i++) entropy += Math.log2(Math.max(1, poolSize - i));
  } else {
    entropy = password.length * Math.log2(poolSize);
  }
  let level;
  if (entropy < 30) level = 'weak';
  else if (entropy < 50) level = 'medium';
  else if (entropy < 70) level = 'strong';
  else level = 'extreme';
  return { entropy, level, poolSize };
}

function pwShowResult(password, length, pools) {
  $('passwordText').textContent = password;
  $('passwordSection').classList.remove('hidden');
  // 结果从「生成密码」那个按钮底下长出来；首屏那一发没有可见的因，不作动效
  if (!suppressReveal) replay($('passwordSection'), 'reveal');
  const { entropy, level, poolSize } = pwCalcStrength(password, pools);
  const segments = $('strengthBar').querySelectorAll('.segment');
  const levels = ['weak', 'medium', 'strong', 'extreme'];
  const levelIdx = levels.indexOf(level);
  segments.forEach((seg, i) => {
    seg.className = 'segment';
    if (i <= levelIdx) seg.classList.add('active', level);
  });
  const labels = { weak: '弱', medium: '中', strong: '强', extreme: '非常强' };
  $('strengthText').textContent = `密码强度：${labels[level]}`;
  $('strengthBits').textContent = `字符池 ${poolSize} · 熵 ${entropy.toFixed(1)} bit`;
}

function pwSyncMinState() {
  $('minUpper').disabled = !$('chkUpper').checked;
  $('minLower').disabled = !$('chkLower').checked;
  $('minDigit').disabled = !$('chkDigit').checked;
  $('minSpecial').disabled = !$('chkSpecial').checked;
}

function wirePasswordEvents() {
  let copyIconTimer = null;
  $('btnCopy').addEventListener('click', function() {
    const text = $('passwordText').textContent;
    if (!text) return;
    copyText(text);
    const tip = $('copyTooltip');
    const use = this.querySelector('use');
    const svg = this.querySelector('svg');
    tip.classList.add('show');
    // 状态翻转：复制图标弹成勾选（onetake press 的 state flip），到点再弹回来
    clearTimeout(copyIconTimer);
    use.setAttribute('href', '#i-check');
    replay(svg, 'pop');
    copyIconTimer = setTimeout(() => {
      tip.classList.remove('show');
      use.setAttribute('href', '#i-copy');
      replay(svg, 'pop');
    }, 1800);
  });
  $('btnGenerate').addEventListener('click', pwGenerate);
  $('pwLength').addEventListener('input', function() { $('lengthDisplay').textContent = this.value; });
  ['chkUpper', 'chkLower', 'chkDigit', 'chkSpecial'].forEach(id => {
    $(id).addEventListener('change', pwSyncMinState);
  });
  pwSyncMinState();
}

/* ══════════ 事件绑定 ══════════ */

function wireEvents(){
  // 标签页
  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => switchTab(tab));
  });

  // 弹窗关闭
  document.querySelectorAll('[data-close]').forEach(btn => {
    btn.addEventListener('click', () => closeModal(btn.dataset.close));
  });
  document.querySelectorAll('.modal-overlay').forEach(ov => {
    // Escape 关闭弹窗：口令弹窗视为取消，确认弹窗视为否定
    ov.addEventListener('keydown', e => {
      if (e.key !== 'Escape') return;
      e.stopPropagation();
      if (ov.id === 'modalPass') resolvePass(null);
      else if (ov.id === 'modalConfirm') resolveConfirm(false);
      else closeModal(ov.id);
    });
  });

  // 管理密钥
  $('btnCreateKey').addEventListener('click', () => { resetPwToggle('cPassword'); openModal('modalCreate'); });
  $('btnCreateFirst').addEventListener('click', () => { resetPwToggle('cPassword'); openModal('modalCreate'); });
  $('btnImportKey').addEventListener('click', openImport);
  $('btnImportFirst').addEventListener('click', openImport);

  // 创建表单
  $('cNeverExpire').addEventListener('change', () => { $('cExpiry').disabled = $('cNeverExpire').checked; });
  $('fmtSelect').addEventListener('change', syncAlgoAvailability);
  $('btnSubmitCreate').addEventListener('click', submitCreate);
  ['cName', 'cEmail'].forEach(id => {
    $(id).addEventListener('keydown', e => {
      if (e.key === 'Enter') { e.preventDefault(); submitCreate(); }
    });
  });

  // 导入
  $('impFileTab').addEventListener('click', () => switchImpTab('file'));
  $('impClipTab').addEventListener('click', () => switchImpTab('clip'));
  $('btnPickFile').addEventListener('click', () => $('impFile').click());
  $('impFile').addEventListener('change', async e => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    try {
      const { parsed, armored } = await readKeyFromFile(file);
      await previewParsed(parsed, armored);
    } catch (err) {
      $('impErr').textContent = friendlyError(err && err.message);
      $('impErr').classList.add('visible');
    }
  });
  $('impClip').addEventListener('input', async () => {
    const text = $('impClip').value.trim();
    if (!text) { $('btnConfirmImport').disabled = true; return; }
    try {
      const parsed = await openpgp.readKey({ armoredKey: text });
      await previewParsed(parsed, text);
    } catch {
      pendingImport = null; // 清掉文件标签页遗留的待导入状态，避免预览与按钮状态不一致
      $('impPreview').classList.add('hidden');
      $('btnConfirmImport').disabled = true;
    }
  });
  $('btnConfirmImport').addEventListener('click', confirmImport);

  // 口令弹窗
  $('passOk').addEventListener('click', () => resolvePass($('passInput').value));
  $('passCancel').addEventListener('click', () => resolvePass(null));
  $('passCancelBtn').addEventListener('click', () => resolvePass(null));
  $('passInput').addEventListener('keydown', e => { if (e.key === 'Enter') resolvePass($('passInput').value); });

  // 确认弹窗
  $('confirmYes').addEventListener('click', () => resolveConfirm(true));
  $('confirmNo').addEventListener('click', () => resolveConfirm(false));
  $('confirmCancel').addEventListener('click', () => resolveConfirm(false));

  // 多标签页同步
  window.addEventListener('storage', e => {
    if (e.key === STORE_KEY) { loadKeys(); renderKeys(); }
  });

  // 记事本
  $('npForOther').addEventListener('change', () => {
    $('npOtherWrap').classList.toggle('hidden', $('npForOther').value !== '__paste');
  });
  $('btnEncrypt').addEventListener('click', doEncrypt);
  $('btnSign').addEventListener('click', doSign);
  $('btnDecrypt').addEventListener('click', doDecrypt);
  $('btnVerify').addEventListener('click', doVerify);
  $('btnCopyOutput').addEventListener('click', () => {
    if ($('npOutput').value) copyText($('npOutput').value);
  });
  $('btnClearOutput').addEventListener('click', () => {
    $('npInput').value = '';
    $('npOutput').value = '';
    $('npStatus').textContent = '';
    $('npStatus').classList.add('hidden');
    $('npOtherKey').value = '';
    $('npOtherWrap').classList.add('hidden');
    $('npForOther').value = '';
    $('npPassword').value = '';
  });

  // 密码框显示切换（眼睛图标）
  // 阻止 mousedown 抢焦点：点击眼睛后焦点留在输入框，Enter 不被吞
  document.addEventListener('mousedown', e => {
    const btn = e.target.closest('.pw-toggle');
    if (btn) e.preventDefault();
  });
  document.addEventListener('click', e => {
    const btn = e.target.closest('.pw-toggle');
    if (!btn) return;
    const input = document.getElementById(btn.dataset.pwFor);
    if (!input) return;
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    btn.setAttribute('aria-label', show ? '隐藏密码' : '显示密码');
    btn.querySelector('use').setAttribute('href', show ? '#i-eye-off' : '#i-eye');
  });
  window.resetPwToggle = function(pwFor){
    const input = document.getElementById(pwFor);
    if (input) input.type = 'password';
    const btn = document.querySelector('.pw-toggle[data-pw-for="' + pwFor + '"]');
    if (btn) {
      btn.setAttribute('aria-label', '显示密码');
      const use = btn.querySelector('use');
      if (use) use.setAttribute('href', '#i-eye');
    }
  };
}

/* ══════════ 初始化 ══════════ */

function init(){
  // 弹窗无障碍标注（role=dialog + aria-label 取标题文本）
  document.querySelectorAll('.modal-overlay .modal').forEach(m => {
    m.setAttribute('role', 'dialog');
    m.setAttribute('aria-modal', 'true');
    const h = m.querySelector('.modal-header h2');
    if (h) m.setAttribute('aria-label', h.textContent);
  });
  // 清理旧版「密码库」遗留数据（该功能已移除）
  try {
    localStorage.removeItem('openpgp_pwlib_v1');
    localStorage.removeItem('pwlib_icon_cache_v1');
  } catch {}
  loadKeys();
  buildAlgoSelect();
  const d = new Date();
  d.setFullYear(d.getFullYear() + 3);
  $('cExpiry').value = fmtDate(d);
  wireEvents();
  renderKeys();
  wirePasswordEvents();
  wireMotion();
  initTabIndicator();
  // 首屏这一发没有可见的因，跳过入场动作（onetake：对着空无一物反应的页面像屏保）
  suppressReveal = true;
  setTimeout(() => { pwGenerate(); suppressReveal = false; }, 50);
  syncScrollbarPad();
  window.addEventListener('resize', syncScrollbarPad);
  if (window.ResizeObserver) new ResizeObserver(syncScrollbarPad).observe(document.body);
}

init();
})();
