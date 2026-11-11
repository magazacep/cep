// ================== Telefon bağlantısı şifrelemesi (masaüstü + telefon ortak) ==================
// Her telefon bağlantısının kendi 256 bit rastgele anahtarı vardır (QR / bağlantı içinde, # sonrası → sunucuya gitmez).
// Veri: JSON → gzip → AES-256-GCM. Sunucu (Supabase) sadece okunamaz veri görür.
const te = new TextEncoder(), td = new TextDecoder();
export const b64u = (bytes) => { let s = ''; const b = new Uint8Array(bytes); for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000)); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
export const unb64u = (s) => { s = String(s).replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return Uint8Array.from(atob(s), c => c.charCodeAt(0)); };
export const newKey = () => b64u(crypto.getRandomValues(new Uint8Array(32)));
export const sha = async (t) => [...new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(t)))].map(b => b.toString(16).padStart(2, '0')).join('');
const imp = (k) => crypto.subtle.importKey('raw', unb64u(k), 'AES-GCM', false, ['encrypt', 'decrypt']);
async function gz(text) {
  if (typeof CompressionStream === 'undefined') return { z: false, bytes: te.encode(text) };
  return { z: true, bytes: new Uint8Array(await new Response(new Blob([text]).stream().pipeThrough(new CompressionStream('gzip'))).arrayBuffer()) };
}
async function ungz(bytes, z) { if (!z) return td.decode(bytes); return await new Response(new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'))).text(); }
export async function pseal(obj, key) {
  const { z, bytes } = await gz(JSON.stringify(obj)); const iv = crypto.getRandomValues(new Uint8Array(12));
  const d = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await imp(key), bytes);
  return JSON.stringify({ f: 'MTKP1', z, i: b64u(iv), d: b64u(d) });
}
export async function popen(text, key) {
  const o = JSON.parse(text); if (o.f !== 'MTKP1') throw new Error('Tanınmayan paket');
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64u(o.i) }, await imp(key), unb64u(o.d));
  return JSON.parse(await ungz(new Uint8Array(plain), o.z));
}
export const linkHash = (id, key) => sha(`mtk-phone|${id}|${key}`);
