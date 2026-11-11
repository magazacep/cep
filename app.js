// ================== Mağaza Takip Cep (telefon) ==================
// Bilgisayardaki Mağaza Takip programının telefona özel, sade yüzü.
// Veri buluttan şifreli gelir (anahtar QR bağlantısında, # sonrası → sunucuya gitmez); telefonda PIN ile kilitlenir.
import { pseal, popen, linkHash, unb64u, b64u } from './pcrypto.js';
import { parseOrderText, splitUnits } from './parse.js';

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const usd = (v) => '$' + (Number(v) || 0).toLocaleString('tr-TR', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const tl = (v) => (Number(v) || 0).toLocaleString('tr-TR', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const num = (v) => { if (v == null || v === '') return 0; let s = String(v).trim().replace(/[^\d.,-]/g, ''); if (s.includes(',')) s = s.replace(/\./g, '').replace(',', '.'); return Number(s) || 0; };
const rid = () => b64u(crypto.getRandomValues(new Uint8Array(9)));
const ago = (iso) => { if (!iso) return '—'; const m = Math.round((Date.now() - new Date(iso)) / 60000); if (m < 1) return 'az önce'; if (m < 60) return `${m} dk önce`; const h = Math.round(m / 60); if (h < 24) return `${h} saat önce`; return new Date(iso).toLocaleString('tr-TR', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }); };
const trDay = (d) => d ? new Date(d + 'T12:00:00').toLocaleDateString('tr-TR', { day: 'numeric', month: 'long' }) : '';
const COUNTRY = { US: 'ABD', GB: 'İngiltere', DE: 'Almanya', FR: 'Fransa', NL: 'Hollanda', IT: 'İtalya', ES: 'İspanya', CA: 'Kanada', AU: 'Avustralya', CH: 'İsviçre', AT: 'Avusturya', BE: 'Belçika', TR: 'Türkiye', SE: 'İsveç', NO: 'Norveç', DK: 'Danimarka', IE: 'İrlanda', PL: 'Polonya', FI: 'Finlandiya', PT: 'Portekiz', NZ: 'Yeni Zelanda', JP: 'Japonya' };
const cName = (c) => COUNTRY[String(c || '').replace(/-.*/, '')] || c || '';
const AUTO = ['girildi', 'paylasildi', 'konsi', 'fatura', 'gonderildi', 'konsi_var'];
const ICON = {
  home: '<path d="M3 11l9-7 9 7v9a1 1 0 0 1-1 1h-5v-6h-6v6H4a1 1 0 0 1-1-1z"/>', list: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
  plus: '<path d="M12 5v14M5 12h14"/>', chart: '<path d="M3 3v18h18M7 15l4-4 3 3 5-6"/>', gear: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>'
};
const icon = (n) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${ICON[n] || ''}</svg>`;

// ---------------------------------------------------------------- yerel saklama (PIN ile şifreli)
const LS = { cfg: 'mtc.cfg', cache: 'mtc.cache', pend: 'mtc.pend' };
const lsGet = (k) => { try { return localStorage.getItem(k); } catch { return null; } };
const lsSet = (k, v) => { try { v == null ? localStorage.removeItem(k) : localStorage.setItem(k, v); } catch { /* özel pencere */ } };
async function pinKey(pin, salt) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(`mtc|${pin}`), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 150000, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function saveCfg(cfg, pin) {
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
  const d = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await pinKey(pin, salt), new TextEncoder().encode(JSON.stringify(cfg)));
  lsSet(LS.cfg, JSON.stringify({ s: b64u(salt), i: b64u(iv), d: b64u(d), n: cfg.n }));
}
async function loadCfg(pin) {
  const o = JSON.parse(lsGet(LS.cfg));
  const p = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64u(o.i) }, await pinKey(pin, unb64u(o.s)), unb64u(o.d));
  return JSON.parse(new TextDecoder().decode(p));
}

// ---------------------------------------------------------------- durum
const S = { cfg: null, hash: '', view: null, viewAt: '', pend: { steps: [], seen: [], etsy: [], add: [] }, tab: 'today', filter: 'acik', q: '', store: '', err: '', busy: false, parsed: null, box: '' };
const me = () => S.view?.link?.user?.username || '';
const role = () => S.view?.link?.role || '';
const isProd = () => role() === 'producer';
const storeOf = (id) => S.view?.stores?.find(s => s.id === id);
const pendCount = () => S.pend.steps.length + S.pend.seen.length + S.pend.etsy.length + S.pend.add.length;

// ---------------------------------------------------------------- bulut
const H = () => { const k = S.cfg.a; const h = { apikey: k, 'Content-Type': 'application/json' }; if (!k.startsWith('sb_')) h.Authorization = `Bearer ${k}`; return h; };
async function api(path, opts = {}) {
  const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), 20000);
  try {
    const r = await fetch(`${S.cfg.u}/rest/v1/${path}`, { ...opts, headers: { ...H(), ...(opts.headers || {}) }, signal: ctrl.signal, cache: 'no-store' });
    if (!r.ok) throw new Error(`Sunucu ${r.status}`);
    const tx = await r.text(); return tx ? JSON.parse(tx) : null;
  } finally { clearTimeout(t); }
}
async function pull() {
  const rows = await api(`mt_packages?select=updated_at,payload&store_hash=eq.${S.hash}&sender=eq.desk`);
  if (!rows?.length) { S.err = 'Bilgisayardan henüz veri gelmedi. Mağaza Takip programı açık ve bulut ayarlı olmalı.'; return; }
  if (rows[0].updated_at === S.viewAt && S.view) { S.err = ''; return; }
  const v = await popen(rows[0].payload, S.cfg.k);
  if (v.kind !== 'phone-view' || v.link?.id !== S.cfg.i) throw new Error('Bu paket bu telefona ait değil');
  S.view = v; S.viewAt = rows[0].updated_at; S.err = '';
  lsSet(LS.cache, await pseal({ v, at: S.viewAt }, S.cfg.k));
  const ap = new Set(v.applied || []); let pruned = false;
  for (const k of ['steps', 'seen', 'etsy', 'add']) { const n = S.pend[k].length; S.pend[k] = S.pend[k].filter(x => !ap.has(x.id)); if (S.pend[k].length !== n) pruned = true; }
  if (pruned) await savePend(false);
}
async function push() {
  const body = { kind: 'phone-changes', v: 1, link: S.cfg.i, at: new Date().toISOString(), ...S.pend };
  const payload = await pseal(body, S.cfg.k);
  await api('mt_packages?on_conflict=store_hash,sender', { method: 'POST', headers: { Prefer: 'resolution=merge-duplicates,return=minimal' }, body: JSON.stringify([{ store_hash: S.hash, sender: 'phone', updated_at: new Date().toISOString(), size: payload.length, payload }]) });
}
let pushT = null;
async function savePend(send = true) {
  lsSet(LS.pend, await pseal(S.pend, S.cfg.k));
  if (send) { clearTimeout(pushT); pushT = setTimeout(() => push().then(() => { S.err = ''; }).catch(e => { S.err = 'Gönderilemedi (internet?): ' + e.message; render(); }), 900); }
}
async function refreshNow(quiet) {
  if (S.busy) return; S.busy = true; if (!quiet) render();
  try { await pull(); if (pendCount()) await push(); } catch (e) { S.err = navigator.onLine === false ? 'İnternet yok. Değişiklikler telefonda bekliyor.' : 'Bağlanılamadı: ' + e.message; }
  S.busy = false; render();
}

// ---------------------------------------------------------------- görünüm yardımcıları (bekleyen değişiklikler dahil)
function stepsOf(o) {
  const out = {};
  for (const t of ['ofis', 'uretim', 'yan']) out[t] = (o.steps[t] || []).map(([k, title, done, at, by]) => {
    const p = [...S.pend.steps].reverse().find(x => x.o === o.id && x.k === k);
    return p ? { k, title, done: !!p.done, at: p.at, by: 'sen (gönderiliyor)', pend: true } : { k, title, done: !!done, at, by };
  });
  return out;
}
const canTick = (o, track) => !!storeOf(o.s)?.ticks?.[track];
function progress(o) { const st = stepsOf(o); const all = [...st.ofis, ...st.uretim, ...st.yan]; const d = all.filter(x => x.done).length; return { d, t: all.length, pct: all.length ? Math.round(d / all.length * 100) : 0 }; }
function nextFor(o) {
  if (o.state === 'teslim') return null; const st = stepsOf(o);
  for (const t of ['ofis', 'uretim', 'yan']) { if (!canTick(o, t)) continue; const n = st[t].find(x => !x.done && !AUTO.includes(x.k)); if (n) return { ...n, track: t }; }
  return null;
}
const isNew = (o) => !!me() && o.by !== me() && !o.seen?.[me()] && !S.pend.seen.some(x => x.o === o.id);
const stLabel = { hazir: 'Hazırlanacak', kargo: 'Kargoda', teslim: 'Teslim' };
const first = (n) => String(n || '').split(' ')[0];
function orderCard(o, extra = '') {
  const pg = progress(o); const s = storeOf(o.s);
  return `<div class="card" data-open="${o.id}"><div class="row"><div class="thumbless">${esc((s?.name || '?').slice(0, 2).toUpperCase())}</div>
    <div class="grow"><div class="bold ell">${esc(o.cust || '—')} · ${esc(cName(o.country))}</div><div class="small muted ell">${esc([o.title, o.size].filter(Boolean).join(' · ') || o.sku || o.code)}</div></div>
    <div style="text-align:right">${isNew(o) ? '<span class="pill new">YENİ</span><br>' : ''}${o.review ? '<span class="pill rev">kontrol</span><br>' : ''}<span class="pill st-${o.state}">${stLabel[o.state]}</span>${o.profit != null ? `<div class="small bold" style="color:${o.profit < 0 ? 'var(--red)' : 'var(--green)'}">${usd(o.profit)}</div>` : ''}</div></div>
    <div class="row" style="margin-top:8px"><div class="bar grow"><i style="width:${pg.pct}%"></i></div><span class="small muted">${pg.d}/${pg.t}</span></div>${extra}</div>`;
}

// ---------------------------------------------------------------- ekranlar
function vToday() {
  const v = S.view; const os = v.orders.filter(o => !S.store || o.s === S.store);
  const fresh = os.filter(isNew);
  const todo = os.map(o => ({ o, n: nextFor(o) })).filter(x => x.n).sort((a, b) => (a.o.due || '9') .localeCompare(b.o.due || '9') || (a.o.date || '').localeCompare(b.o.date || '')).slice(0, 25);
  const sums = (v.sum || []).filter(x => !S.store || x.s === S.store);
  const tot = sums.reduce((a, x) => ({ rev: a.rev + x.rev, mine: a.mine + x.mine, count: a.count + x.count }), { rev: 0, mine: 0, count: 0 });
  return `<h2>Merhaba ${esc(first(v.link.user?.name || v.link.name))}</h2>
    ${v.sum ? `<div class="stats"><div class="card"><div class="k">Bu ay satış</div><div class="v">${usd(tot.rev)}</div><div class="small muted">${tot.count} sipariş</div></div><div class="card"><div class="k">Bu ay elime geçen</div><div class="v" style="color:var(--green)">${usd(tot.mine)}</div><div class="small muted">giderler düşülmüş</div></div></div>` : ''}
    ${fresh.length ? `<h3>Yeni gelen siparişler (${fresh.length})</h3>${fresh.map(o => orderCard(o, `<button class="btn g w" style="margin-top:10px" data-seen="${o.id}">✓ Gördüm</button>`)).join('')}
      ${fresh.length > 1 ? `<button class="btn w" data-seenall>Hepsini gördüm</button>` : ''}` : ''}
    <h3>Sıradaki işler ${todo.length ? `(${todo.length})` : ''}</h3>
    ${todo.length ? todo.map(({ o, n }) => `<div class="card"><div class="row"><div class="grow"><div class="bold ell">${esc(n.title)}</div><div class="small muted ell">${esc(o.cust || '')} · ${esc(cName(o.country))} · ${esc(o.title || o.sku || '')} ${esc(o.size || '')}</div>${o.due ? `<div class="small" style="color:var(--yellow)">son gönderim ${trDay(o.due)}</div>` : ''}</div>
      <button class="btn g sm" data-tick="${o.id}|${n.k}|1">✓ Yapıldı</button></div></div>`).join('') : `<div class="empty">Bekleyen iş yok 👍</div>`}`;
}
function vOrders() {
  const v = S.view; const q = S.q.toLocaleLowerCase('tr');
  let os = v.orders.filter(o => !S.store || o.s === S.store);
  if (S.filter === 'acik') os = os.filter(o => o.state !== 'teslim'); else if (S.filter !== 'hepsi') os = os.filter(o => o.state === S.filter);
  if (q) os = os.filter(o => [o.cust, o.code, o.sku, o.title, cName(o.country)].join(' ').toLocaleLowerCase('tr').includes(q));
  return `<div class="chips">${[['acik', 'Açık'], ['hazir', 'Hazırlanacak'], ['kargo', 'Kargoda'], ['teslim', 'Teslim'], ['hepsi', 'Hepsi']].map(([k, t]) => `<button data-filter="${k}" class="${S.filter === k ? 'on' : ''}">${t}</button>`).join('')}</div>
    <input id="q" placeholder="Ara: müşteri, SKU, kod…" value="${esc(S.q)}" style="margin-bottom:10px">
    ${os.length ? os.slice(0, 120).map(o => orderCard(o)).join('') : '<div class="empty">Sipariş yok</div>'}`;
}
function vDetail(o) {
  const st = stepsOf(o); const s = storeOf(o.s);
  const sec = (t, name) => st[t].length ? `<h3>${name}${canTick(o, t) ? '' : ' · 🔒'}</h3><div class="card">${st[t].map(x => `<div class="step ${x.done ? 'done' : ''} ${canTick(o, t) ? '' : 'lock'}" ${canTick(o, t) ? `data-tick="${o.id}|${x.k}|${x.done ? 0 : 1}"` : ''}><span class="cb">${x.done ? '✓' : ''}</span><div class="grow"><div>${esc(x.title)}</div>${x.done && (x.at || x.by) ? `<div class="w">${esc(x.by || '')} ${x.at ? '· ' + ago(x.at) : ''}</div>` : ''}</div></div>`).join('')}</div>` : '';
  return `<div class="row"><div class="grow"><div class="bold" style="font-size:18px">${esc(o.cust || '—')}</div><div class="small muted">${esc(s?.name || '')} · ${esc(o.code || '')} · ${trDay(o.date)}</div></div><button class="btn sm" data-close>Kapat</button></div>
    ${isNew(o) ? `<button class="btn g w" style="margin-top:12px" data-seen="${o.id}">✓ Gördüm</button>` : ''}
    ${o.review ? `<div class="card warn" style="margin-top:12px">Telefondan eklendi; bilgisayarda maliyeti kontrol edilecek.</div>` : ''}
    <div class="card" style="margin-top:12px"><div class="bold">${esc(o.title || '—')}</div>
      <div class="small">${[o.size && `Ölçü: <b>${esc(o.size)}</b>`, o.sku && `SKU: <b>${esc(o.sku)}</b>`, o.feat && esc(o.feat), o.part && `Parça: ${esc(o.part)}`].filter(Boolean).join('<br>')}</div>
      <div class="small muted" style="margin-top:6px">${esc(cName(o.country))}${o.due ? ` · son gönderim <b>${trDay(o.due)}</b>` : ''}</div>
      ${o.note ? `<div class="card warn small" style="margin:8px 0 0">${esc(o.note)}</div>` : ''}
      ${o.sub != null ? `<div class="row small" style="margin-top:8px"><span>Satış <b>${usd(o.sub)}</b></span><span>Kâr <b style="color:${o.profit < 0 ? 'var(--red)' : 'var(--green)'}">${usd(o.profit)}</b></span>${o.track ? `<span class="ell">Takip: ${esc(o.track)}</span>` : ''}</div>` : ''}</div>
    ${sec('uretim', 'Üretim')}${sec('ofis', 'Ofis')}${sec('yan', 'Yan işler')}`;
}
function vAdd() {
  const ms = S.view.stores.filter(s => s.manage);
  if (!ms.length) return '<div class="empty">Sipariş ekleme yetkin olan mağaza yok.</div>';
  const p = S.parsed; let pv = '';
  if (p) {
    const units = splitUnits(p);
    pv = `<div class="card ${p.missing?.length ? 'warn' : ''}"><div class="bold">${esc(p.buyerName || 'Alıcı bulunamadı')} · ${esc(cName(p.country))}</div>
      <div class="small muted">Etsy #${esc(p.orderNo || '?')} · ${esc(p.orderDate || '')}</div>
      ${(p.items || []).map(it => `<div class="small" style="margin-top:6px">• ${esc(String(it.title || '').split(',')[0].slice(0, 60))}${it.wCm ? ` · ${it.wCm}×${it.hCm}` : ''}${it.sku ? ` · <b>${esc(it.sku)}</b>` : ''}${it.qty > 1 ? ` · ${it.qty} adet` : ''}</div>`).join('')}
      <div class="small" style="margin-top:6px">Toplam: <b>${p.money?.itemTotal != null ? usd(p.money.itemTotal) : '—'}</b> · ${units.length} sipariş satırı</div>
      ${p.missing?.length ? `<div class="small" style="margin-top:6px;color:var(--yellow)">Eksik: ${esc(p.missing.join(', '))} (bilgisayarda tamamlanır)</div>` : ''}</div>
      ${units.length > 1 ? `<div class="chips"><button data-box="tek" class="${S.box === 'tek' ? 'on' : ''}">Tek kutu</button><button data-box="ayri" class="${S.box === 'ayri' ? 'on' : ''}">Ayrı kutular</button></div>` : ''}
      <button class="btn g w" id="send-add" ${units.length > 1 && !S.box ? 'disabled' : ''}>Siparişi gönder</button>`;
  }
  const pa = S.pend.add;
  return `<h2>Sipariş ekle</h2>
    <label class="f">Mağaza<select id="add-s">${ms.map(s => `<option value="${s.id}" ${S.addStore === s.id ? 'selected' : ''}>${esc(s.name)}</option>`).join('')}</select></label>
    <label class="f">Etsy sipariş sayfasının yazısı<textarea id="add-t" placeholder="Etsy uygulamasında siparişi aç → yazıları seç-kopyala (ya da Google Lens ile ekran görüntüsünden metni kopyala) → buraya yapıştır">${esc(S.addText || '')}</textarea></label>
    <button class="btn p w" id="parse">Oku</button><div style="height:10px"></div>${pv}
    ${pa.length ? `<h3>Bilgisayara gidiyor (${pa.length})</h3>${pa.map(x => `<div class="card small">${esc(storeOf(x.s)?.name || '')} · ${esc(x.label || '')} <span class="muted">· ${ago(x.at)}</span></div>`).join('')}<div class="small muted">Bilgisayardaki program açıkken birkaç dakikada eklenir; maliyeti orada kontrol edilir.</div>` : ''}`;
}
function vEtsy() {
  const v = S.view; const list = Object.entries(v.etsy || {}).filter(([id]) => !S.store || id === S.store);
  if (!list.length) return '<div class="empty">Etsy mağazası yok.</div>';
  return `<h2>Etsy değerleri</h2><div class="small muted" style="margin-bottom:10px">Etsy panelindeki <b>bu ayın toplamını</b> (₺) her gün güncelle.</div>
    ${list.map(([id, e]) => { const pe = (k) => [...S.pend.etsy].reverse().find(x => x.s === id && x.k === k); const val = (k) => pe(k) ? pe(k).v : e[k];
      const sales = +val('sales') || 0, cost = (+val('fee') || 0) + (+val('marketing') || 0);
      return `<div class="card"><div class="row"><div class="grow bold">${esc(storeOf(id)?.name || '')}</div>${sales ? `<span class="pill ${cost / sales * 100 <= 15 ? 'st-teslim' : cost / sales * 100 <= 22 ? 'st-hazir' : 'new'}">%${tl(cost / sales * 100)}</span>` : ''}</div>
        <div class="small muted" style="margin-bottom:8px">${e.at ? `son: ${ago(e.at)} · ${esc(e.by)}` : 'henüz girilmedi'}</div>
        ${[['sales', 'Sales'], ['fee', 'Fee'], ['marketing', 'Marketing']].map(([k, t]) => `<label class="f">${t} (₺)<input inputmode="decimal" data-etsy="${id}|${k}" value="${val(k) != null && val(k) !== '' ? tl(val(k)) : ''}" placeholder="0,00"></label>`).join('')}</div>`; }).join('')}
    <button class="btn p w" id="etsy-save">Kaydet</button>`;
}
function vSettings() {
  const v = S.view;
  return `<h2>Ayarlar</h2><div class="card"><div class="bold">${esc(v?.link?.name || S.cfg.n || '')}</div><div class="small muted">${{ owner: 'Sahip', manager: 'Ortak / yönetici', producer: 'Üretici / iş takipçisi' }[role()] || ''}</div>
    <div class="small" style="margin-top:8px">Mağazalar: ${esc((v?.stores || []).map(s => s.name).join(', '))}</div>
    <div class="small muted" style="margin-top:8px">Bilgisayardan son veri: ${ago(v?.at)}<br>Bekleyen değişiklik: ${pendCount()}</div></div>
    <button class="btn w" id="lock">Kilitle</button><div style="height:10px"></div>
    <button class="btn w" id="forget" style="color:var(--red)">Bu telefondan bağlantıyı sil</button>
    <div class="small muted center" style="margin-top:18px">Mağaza Takip Cep · veri uçtan uca şifreli</div>`;
}

// ---------------------------------------------------------------- çizim
function render() {
  const app = $('#app');
  if (!S.view) { app.innerHTML = `<main><div class="card ${S.err ? 'err' : ''}" style="margin-top:30px">${S.busy ? 'Bilgisayardan veriler alınıyor…' : esc(S.err || 'Bekleniyor…')}</div>${S.busy ? '' : '<button class="btn p w" id="retry">Tekrar dene</button>'}</main>`; $('#retry')?.addEventListener('click', () => refreshNow()); return; }
  const v = S.view; const canAdd = v.stores.some(s => s.manage); const hasEtsy = !!v.etsy && Object.keys(v.etsy).length;
  const nNew = v.orders.filter(isNew).length;
  const tabs = [['today', 'Bugün', 'home', nNew], ['orders', 'Siparişler', 'list'], ...(canAdd ? [['add', 'Ekle', 'plus']] : []), ...(hasEtsy ? [['etsy', 'Etsy', 'chart']] : []), ['set', 'Ayarlar', 'gear']];
  const body = { today: vToday, orders: vOrders, add: vAdd, etsy: vEtsy, set: vSettings }[S.tab]?.() || '';
  const pc = pendCount();
  app.innerHTML = `<header><img src="icon-192.png" alt=""><div class="grow"><div class="t">Mağaza Cep</div><div class="s">${S.busy ? 'yenileniyor…' : `güncel: ${ago(v.at)}`}${pc ? ` · ${pc} değişiklik gönderiliyor` : ''}</div></div>
    ${v.stores.length > 1 ? `<select id="st" style="width:auto;max-width:42%;background:rgba(255,255,255,.15);color:#fff;border:0;padding:8px"><option value="" style="color:#000">Tüm mağazalar</option>${v.stores.map(s => `<option value="${s.id}" ${S.store === s.id ? 'selected' : ''} style="color:#000">${esc(s.name)}</option>`).join('')}</select>` : ''}
    <button id="rf">⟳</button></header>
    <main>${S.err ? `<div class="card warn small">${esc(S.err)}</div>` : ''}${body}</main>
    <nav>${tabs.map(([k, t, i, b]) => `<button data-tab="${k}" class="${S.tab === k ? 'on' : ''}">${icon(i)}${t}${b ? `<i class="b">${b}</i>` : ''}</button>`).join('')}</nav>`;
  bind();
}
function toast(t) { const d = document.createElement('div'); d.className = 'toast'; d.textContent = t; document.body.appendChild(d); setTimeout(() => d.remove(), 2600); }
function openSheet(id) {
  const o = S.view.orders.find(x => x.id === id); if (!o) return;
  const sh = document.createElement('div'); sh.className = 'sheet'; sh.innerHTML = `<div>${vDetail(o)}</div>`; document.body.appendChild(sh);
  sh.addEventListener('click', (e) => { if (e.target === sh || e.target.closest('[data-close]')) { sh.remove(); render(); return; } const t = e.target.closest('[data-tick],[data-seen]'); if (t) { act(t); sh.querySelector('div').innerHTML = vDetail(o); } });
}
async function act(el) {
  if (el.dataset.tick) {
    const [o, k, d] = el.dataset.tick.split('|');
    S.pend.steps.push({ id: rid(), o, k, done: d === '1', at: new Date().toISOString() });
    // aynı adımın eski bekleyen kayıtları gereksiz
    const last = new Map(); S.pend.steps.forEach(x => last.set(x.o + x.k, x.id)); S.pend.steps = S.pend.steps.filter(x => last.get(x.o + x.k) === x.id);
    toast(d === '1' ? 'İşaretlendi ✓' : 'İşaret kaldırıldı'); await savePend();
  } else if (el.dataset.seen) {
    if (!S.pend.seen.some(x => x.o === el.dataset.seen)) S.pend.seen.push({ id: rid(), o: el.dataset.seen, at: new Date().toISOString() });
    toast('Gördüm kaydedildi'); await savePend();
  }
}
function bind() {
  $$('[data-tab]').forEach(b => b.onclick = () => { S.tab = b.dataset.tab; render(); window.scrollTo(0, 0); });
  $('#rf')?.addEventListener('click', () => refreshNow());
  $('#st')?.addEventListener('change', (e) => { S.store = e.target.value; render(); });
  $$('[data-open]').forEach(c => c.addEventListener('click', (e) => { if (e.target.closest('button')) return; openSheet(c.dataset.open); }));
  $$('[data-tick],[data-seen]').forEach(b => b.addEventListener('click', async (e) => { e.stopPropagation(); await act(b); render(); }));
  $('[data-seenall]')?.addEventListener('click', async () => { for (const o of S.view.orders.filter(isNew)) S.pend.seen.push({ id: rid(), o: o.id, at: new Date().toISOString() }); await savePend(); toast('Hepsi görüldü'); render(); });
  $$('[data-filter]').forEach(b => b.onclick = () => { S.filter = b.dataset.filter; render(); });
  const q = $('#q'); if (q) q.oninput = () => { S.q = q.value; const pos = q.selectionStart; render(); const n = $('#q'); n.focus(); n.setSelectionRange(pos, pos); };
  // ekle
  const at = $('#add-t'); if (at) at.oninput = () => { S.addText = at.value; };
  $('#add-s')?.addEventListener('change', (e) => { S.addStore = e.target.value; });
  $('#parse')?.addEventListener('click', () => { const t = $('#add-t').value; if (!t.trim()) return toast('Önce sipariş yazısını yapıştır'); try { S.parsed = parseOrderText(t); S.box = ''; } catch (e) { toast('Okunamadı: ' + e.message); } render(); });
  $$('[data-box]').forEach(b => b.onclick = () => { S.box = b.dataset.box; render(); });
  $('#send-add')?.addEventListener('click', async () => {
    const p = S.parsed; const sid = $('#add-s').value;
    S.pend.add.push({ id: rid(), s: sid, text: S.addText, box: S.box || '', at: new Date().toISOString(), label: `${p.buyerName || ''} #${p.orderNo || ''}` });
    S.parsed = null; S.addText = ''; S.box = ''; await savePend(); toast('Gönderildi, bilgisayara iletiliyor'); render();
  });
  // etsy
  $('#etsy-save')?.addEventListener('click', async () => {
    let n = 0;
    for (const i of $$('[data-etsy]')) { const [s, k] = i.dataset.etsy.split('|'); if (i.value.trim() === '') continue; const v = num(i.value); const cur = S.view.etsy[s]?.[k]; const pe = [...S.pend.etsy].reverse().find(x => x.s === s && x.k === k); if ((pe ? pe.v : cur) === v) continue; S.pend.etsy.push({ id: rid(), s, k, m: S.view.month, v, at: new Date().toISOString() }); n++; }
    if (!n) return toast('Değişiklik yok'); await savePend(); toast('Kaydedildi'); render();
  });
  $('#lock')?.addEventListener('click', () => location.reload());
  $('#forget')?.addEventListener('click', () => { if (confirm('Bu telefondaki bağlantı silinsin mi? Tekrar bağlanmak için yeni QR gerekir.')) { Object.values(LS).forEach(k => lsSet(k, null)); location.reload(); } });
}

// ---------------------------------------------------------------- açılış: bağlantı + PIN
function pinScreen({ title, sub, onPin, second }) {
  $('#app').innerHTML = `<main style="padding-top:40px"><div class="center"><img src="icon-192.png" style="width:72px;border-radius:18px" alt=""><h2>${esc(title)}</h2><div class="muted small">${sub}</div></div>
    <div class="card" style="margin-top:20px"><input id="pin" class="pin" type="password" inputmode="numeric" maxlength="6" autocomplete="off" placeholder="••••">
    <button class="btn p w" id="go" style="margin-top:12px">Devam</button><div id="perr" class="small center" style="color:var(--red);margin-top:8px"></div></div>${second || ''}</main>`;
  const go = async () => { const v = $('#pin').value.trim(); if (!/^\d{4,6}$/.test(v)) { $('#perr').textContent = '4-6 haneli rakam gir'; return; } $('#go').disabled = true; try { await onPin(v); } catch (e) { $('#perr').textContent = e.message || 'Hata'; $('#go').disabled = false; } };
  $('#go').onclick = go; $('#pin').onkeydown = (e) => { if (e.key === 'Enter') go(); }; setTimeout(() => $('#pin').focus(), 50);
}
async function start(cfg) {
  S.cfg = cfg; S.hash = await linkHash(cfg.i, cfg.k);
  try { const c = lsGet(LS.cache); if (c) { const x = await popen(c, cfg.k); S.view = x.v; S.viewAt = x.at; } } catch { /* yok */ }
  try { const p = lsGet(LS.pend); if (p) S.pend = { steps: [], seen: [], etsy: [], add: [], ...(await popen(p, cfg.k)) }; } catch { /* yok */ }
  render(); refreshNow(true);
  setInterval(() => { if (document.visibilityState === 'visible') refreshNow(true); }, 60000);
  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') refreshNow(true); });
  window.addEventListener('online', () => refreshNow(true));
}
async function boot() {
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
  const m = location.hash.match(/c=([A-Za-z0-9_-]+)/);
  if (m) {
    let cfg; try { cfg = JSON.parse(new TextDecoder().decode(unb64u(m[1]))); } catch { cfg = null; }
    history.replaceState(null, '', location.pathname);
    if (!cfg?.u || !cfg?.k || !cfg?.i) { $('#app').innerHTML = '<main><div class="card err">Bağlantı bozuk. Bilgisayardan yeni QR iste.</div></main>'; return; }
    let firstPin = '';
    const ask = () => pinScreen({ title: 'Telefonu bağla', sub: `<b>${esc(cfg.n || '')}</b><br>Bu telefona 4-6 haneli bir PIN belirle. Uygulamayı her açtığında sorulur.`, onPin: async (p) => {
      if (!firstPin) { firstPin = p; pinScreen({ title: 'PIN tekrar', sub: 'Aynı PIN\'i bir daha yaz', onPin: async (p2) => { if (p2 !== firstPin) { firstPin = ''; throw new Error('PIN\'ler aynı değil, baştan'); } await saveCfg(cfg, p2); lsSet(LS.cache, null); lsSet(LS.pend, null); toast('Bağlandı'); start(cfg); } }); }
    } });
    ask(); return;
  }
  if (!lsGet(LS.cfg)) {
    $('#app').innerHTML = `<main style="padding-top:40px" class="center"><img src="icon-192.png" style="width:80px;border-radius:20px" alt=""><h2>Mağaza Takip Cep</h2><div class="card muted">Bu telefon henüz bağlı değil.<br><br>Bilgisayardaki Mağaza Takip programında <b>Daha fazla → Telefon (Cep)</b> bölümünden QR oluştur ve telefonun kamerasıyla okut.</div></main>`;
    return;
  }
  let tries = 0;
  pinScreen({ title: 'Mağaza Takip Cep', sub: esc(JSON.parse(lsGet(LS.cfg)).n || '') + '<br>PIN\'ini gir', onPin: async (p) => {
    try { const cfg = await loadCfg(p); start(cfg); } catch { tries++; await new Promise(r => setTimeout(r, Math.min(8000, 400 * 2 ** tries))); throw new Error('PIN yanlış'); }
  }, second: '<div class="center small muted" style="margin-top:16px"><a href="#" id="reset" style="color:var(--muted)">PIN\'i unuttum (bağlantıyı sil)</a></div>' });
  $('#reset').onclick = (e) => { e.preventDefault(); if (confirm('Bağlantı silinsin mi? Bilgisayardan yeni QR gerekir.')) { Object.values(LS).forEach(k => lsSet(k, null)); location.reload(); } };
}
boot();
