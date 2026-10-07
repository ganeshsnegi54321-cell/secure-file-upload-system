/* ==========================================================================
   UI-ONLY VERSION: the page layout/menus/forms are rendered, but every
   encryption/decryption function and every button handler is commented out.
   To bring a function back, remove the leading '// ' from its lines.
   ========================================================================== */

/* ==========================================================================
   Cipher Lab - script.js
   Structure:
     1. Helpers
     2. Classical ciphers (pure JS, A-Z)
     3. Modern symmetric (CryptoJS + hand-written ChaCha20)
     4. Asymmetric (JSEncrypt for RSA, Web Crypto API for ECC/ECDSA, BigInt for DH)
     5. ALGOS registry (describes each algorithm's form fields and run function)
     6. UI engine (renders the registry, handles buttons)
   ========================================================================== */

// /* ---------- 1. HELPERS ---------- */
// const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
// const mod = (n, m) => ((n % m) + m) % m;                 // true modulo (never negative)
// const fail = msg => { throw new Error(msg); };            // all errors shown in red under the button
// const gcd = (a, b) => (b ? gcd(b, a % b) : Math.abs(a));
// const modInv = (a, m) => { for (let i = 1; i < m; i++) if (mod(a * i, m) === 1) return i; return -1; };
// const enc8 = s => new TextEncoder().encode(s);
// const dec8 = b => new TextDecoder().decode(b);
// const toB64 = b => btoa(String.fromCharCode(...new Uint8Array(b)));
// const fromB64 = s => Uint8Array.from(atob(s.trim()), c => c.charCodeAt(0));

// /** Parse an integer field strictly (rejects letters, decimals, empty). */
// function int(v, name) {
//   if (!/^-?\d+$/.test(String(v).trim())) fail(`${name} must be a whole number.`);
//   return parseInt(v, 10);
// }

// /** Apply fn(letterIndex, position) to every letter, keep case, leave other characters untouched. */
// function mapLetters(text, fn) {
//   let pos = 0;
//   return text.replace(/[a-z]/gi, ch => {
//     const base = ch <= 'Z' ? 65 : 97;                      // uppercase or lowercase ASCII start
//     return String.fromCharCode(base + mod(fn(ch.charCodeAt(0) - base, pos++), 26));
//   });
// }

// /* ---------- 2. CLASSICAL CIPHERS ---------- */

// // Caesar: C = (P + k) mod 26    |   P = (C - k) mod 26
// function caesar(enc, text, c) {
//   const k = int(c.shift, 'Shift');
//   return mapLetters(text, p => p + (enc ? k : -k));
// }

// // Affine: C = (a*P + b) mod 26  |  P = a^-1 * (C - b) mod 26. 'a' must be coprime with 26.
// function affine(enc, text, c) {
//   const a = int(c.a, 'Key a'), b = int(c.b, 'Key b');
//   if (gcd(a, 26) !== 1) fail('Key a must be coprime with 26 (valid: 1,3,5,7,9,11,15,17,19,21,23,25).');
//   const inv = modInv(mod(a, 26), 26);                       // modular inverse of a, needed for decryption
//   return mapLetters(text, p => (enc ? a * p + b : inv * (p - b)));
// }

// // Vigenere: Caesar with a different shift per letter, taken from the repeating keyword.
// function vigenere(enc, text, c) {
//   const key = c.key.toUpperCase().replace(/[^A-Z]/g, '');
//   if (!key) fail('Keyword must contain at least one letter.');
//   return mapLetters(text, (p, i) => p + (enc ? 1 : -1) * (key.charCodeAt(i % key.length) - 65));
// }

// // Playfair: 5x5 square from the keyword (I and J share a cell); letters are encrypted in pairs.
// function playfair(enc, text, c) {
//   const key = c.key.toUpperCase().replace(/J/g, 'I').replace(/[^A-Z]/g, '');
//   if (!key) fail('Keyword must contain at least one letter.');
//   const sq = [...new Set((key + A.replace('J', '')).split(''))];  // keyword letters first, no duplicates
//   const pos = ch => { const i = sq.indexOf(ch); return [Math.floor(i / 5), i % 5]; };
//   const s = text.toUpperCase().replace(/J/g, 'I').replace(/[^A-Z]/g, '');
//   if (!s) fail('Input must contain letters.');
//   const pairs = [];
//   if (enc) {
//     // Split into digraphs; insert filler X between identical letters and pad the last letter.
//     for (let i = 0; i < s.length;) {
//       const a = s[i], b = s[i + 1];
//       if (b === undefined || a === b) { pairs.push([a, 'X']); i++; } else { pairs.push([a, b]); i += 2; }
//     }
//   } else {
//     if (s.length % 2) fail('Playfair ciphertext must have an even number of letters.');
//     for (let i = 0; i < s.length; i += 2) pairs.push([s[i], s[i + 1]]);
//   }
//   const d = enc ? 1 : -1;                                   // +1 moves right/down, -1 moves left/up
//   return pairs.map(([a, b]) => {
//     const [r1, c1] = pos(a), [r2, c2] = pos(b);
//     if (r1 === r2) return sq[r1 * 5 + mod(c1 + d, 5)] + sq[r2 * 5 + mod(c2 + d, 5)]; // same row
//     if (c1 === c2) return sq[mod(r1 + d, 5) * 5 + c1] + sq[mod(r2 + d, 5) * 5 + c2]; // same column
//     return sq[r1 * 5 + c2] + sq[r2 * 5 + c1];                                        // rectangle: swap columns
//   }).join('');
// }

// // Hill: blocks of n letters are multiplied by an n x n key matrix mod 26. Decrypt uses the inverse matrix.
// const minor = (m, r, c) => m.filter((_, i) => i !== r).map(row => row.filter((_, j) => j !== c));
// const det = m => (m.length === 1 ? m[0][0] : m[0].reduce((s, v, j) => s + (j % 2 ? -1 : 1) * v * det(minor(m, 0, j)), 0));

// function hill(enc, text, c) {
//   const nums = c.key.split(/[\s,;]+/).filter(Boolean).map(Number);
//   const n = Math.sqrt(nums.length);
//   if (![2, 3].includes(n) || nums.some(x => !Number.isInteger(x))) fail('Key must be 4 numbers (2x2) or 9 numbers (3x3), e.g. 3 3 2 5.');
//   let M = Array.from({ length: n }, (_, i) => nums.slice(i * n, i * n + n));
//   const dInv = modInv(mod(det(M), 26), 26);                 // inverse of determinant mod 26
//   if (dInv < 0) fail('Key matrix is not invertible mod 26 (determinant shares a factor with 26).');
//   if (!enc) {
//     // Inverse = det^-1 * adjugate (transposed cofactor matrix), all mod 26
//     M = M.map((row, i) => row.map((_, j) => mod((((i + j) % 2) ? -1 : 1) * det(minor(M, j, i)) * dInv, 26)));
//   }
//   let s = text.toUpperCase().replace(/[^A-Z]/g, '');
//   if (!s) fail('Input must contain letters.');
//   if (!enc && s.length % n) fail(`Ciphertext length must be a multiple of ${n}.`);
//   while (s.length % n) s += 'X';                            // pad the last block with X
//   let out = '';
//   for (let i = 0; i < s.length; i += n) {
//     const v = [...s.slice(i, i + n)].map(ch => ch.charCodeAt(0) - 65);
//     for (let r = 0; r < n; r++) out += A[mod(M[r].reduce((sum, k, j) => sum + k * v[j], 0), 26)];
//   }
//   return out;
// }

// /* ---------- 3. MODERN SYMMETRIC ---------- */

// /** CryptoJS passphrase mode: random salt -> key+IV derived with EVP_BytesToKey (MD5); output is OpenSSL-style Base64. */
// function cryptoJsCipher(name) {
//   return async (enc, text, c) => {
//     if (!c.key) fail('Secret key is required.');
//     if (enc) return CryptoJS[name].encrypt(text, c.key).toString();
//     let plain = '';
//     try { plain = CryptoJS[name].decrypt(text.trim(), c.key).toString(CryptoJS.enc.Utf8); } catch (e) { /* handled below */ }
//     if (!plain) fail('Decryption failed: wrong key or invalid ciphertext.');
//     return plain;
//   };
// }

// /** ChaCha20 (RFC 8439), written by hand because CryptoJS does not include it. */
// function chacha20(key, nonce, counter, data) {
//   const rotl = (x, n) => (x << n) | (x >>> (32 - n));
//   const le = (b, i) => b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24);
//   // State: 4 constants ("expand 32-byte k"), 8 key words, 1 counter, 3 nonce words
//   const st = new Uint32Array([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
//     ...Array.from({ length: 8 }, (_, i) => le(key, i * 4)), counter,
//     ...Array.from({ length: 3 }, (_, i) => le(nonce, i * 4))]);
//   const out = new Uint8Array(data.length);
//   for (let off = 0; off < data.length; off += 64) {
//     const w = st.slice();                                   // Uint32Array arithmetic wraps mod 2^32 automatically
//     const qr = (a, b, c, d) => {                            // quarter round: add, xor, rotate
//       w[a] += w[b]; w[d] = rotl(w[d] ^ w[a], 16);
//       w[c] += w[d]; w[b] = rotl(w[b] ^ w[c], 12);
//       w[a] += w[b]; w[d] = rotl(w[d] ^ w[a], 8);
//       w[c] += w[d]; w[b] = rotl(w[b] ^ w[c], 7);
//     };
//     for (let r = 0; r < 10; r++) {                          // 10 double rounds = 20 rounds
//       qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15);  // column rounds
//       qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14);  // diagonal rounds
//     }
//     for (let i = 0; i < 16; i++) w[i] += st[i];             // add original state -> 64-byte keystream block
//     const ks = new Uint8Array(w.buffer);
//     for (let i = 0; i < 64 && off + i < data.length; i++) out[off + i] = data[off + i] ^ ks[i];  // XOR = encrypt/decrypt
//     st[12]++;                                               // next block counter
//   }
//   return out;
// }

// async function chachaRun(enc, text, c) {
//   if (!c.key) fail('Secret key is required.');
//   // Derive a 256-bit key from the passphrase with SHA-256
//   const key = new Uint8Array(await crypto.subtle.digest('SHA-256', enc8(c.key)));
//   if (enc) {
//     const nonce = crypto.getRandomValues(new Uint8Array(12));          // random 96-bit nonce, never reuse with the same key
//     const ct = chacha20(key, nonce, 1, enc8(text));
//     return toB64([...nonce, ...ct]);                                   // output = nonce || ciphertext
//   }
//   let raw;
//   try { raw = fromB64(text); } catch (e) { fail('Ciphertext is not valid Base64.'); }
//   if (raw.length < 13) fail('Ciphertext is too short.');
//   try { return new TextDecoder('utf-8', { fatal: true }).decode(chacha20(key, raw.slice(0, 12), 1, raw.slice(12))); }
//   catch (e) { fail('Decryption failed: wrong key or corrupted ciphertext.'); }
// }

// /* ---------- 4. ASYMMETRIC ---------- */

// // --- RSA (JSEncrypt, PKCS#1 v1.5 padding) ---
// function rsaGenerate(set, c) {
//   const crypt = new JSEncrypt({ default_key_size: c.size });
//   return new Promise(res => crypt.getKey(() => {            // async key generation keeps the page responsive
//     set('pub', crypt.getPublicKey()); set('priv', crypt.getPrivateKey()); res();
//   }));
// }
// async function rsaRun(enc, text, c) {
//   const j = new JSEncrypt();
//   if (enc) {
//     if (!c.pub.trim()) fail('Paste or generate a public key first.');
//     j.setPublicKey(c.pub);
//     const r = j.encrypt(text);
//     if (!r) fail('Encryption failed: invalid public key, or text too long for this key size (1024-bit: about 117 bytes).');
//     return r;
//   }
//   if (!c.priv.trim()) fail('Paste or generate a private key first.');
//   j.setPrivateKey(c.priv);
//   const r = j.decrypt(text.trim());
//   if (r === false || r === null) fail('Decryption failed: the private key does not match this ciphertext.');
//   return r;
// }

// // --- ECC and ECDSA (Web Crypto API, curve P-256; keys are exchanged as JSON Web Keys) ---
// const subtle = crypto.subtle;
// const jwk = k => subtle.exportKey('jwk', k).then(JSON.stringify);
// const parseJwk = (s, what) => { try { return JSON.parse(s); } catch (e) { return fail(`${what} must be a valid JWK (JSON).`); } };
// const importKey = (s, what, algo, usage) => subtle.importKey('jwk', parseJwk(s, what), { name: algo, namedCurve: 'P-256' }, true, usage)
//   .catch(() => fail(`${what} is not a valid P-256 key.`));

// async function eccGenerate(set) {
//   const kp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
//   set('pub', await jwk(kp.publicKey)); set('priv', await jwk(kp.privateKey));
// }
// // ECIES-style hybrid scheme: ephemeral ECDH -> shared secret -> AES-256-GCM encrypts the message.
// const aesFrom = (priv, pub, usage) => subtle.deriveKey({ name: 'ECDH', public: pub }, priv, { name: 'AES-GCM', length: 256 }, false, [usage]);
// async function eccRun(enc, text, c) {
//   if (enc) {
//     const pub = await importKey(c.pub, 'Public key', 'ECDH', []);
//     const eph = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
//     const iv = crypto.getRandomValues(new Uint8Array(12));
//     const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, await aesFrom(eph.privateKey, pub, 'encrypt'), enc8(text));
//     return toB64(enc8(JSON.stringify({ epk: parseJwk(await jwk(eph.publicKey)), iv: toB64(iv), ct: toB64(ct) })));
//   }
//   const priv = await importKey(c.priv, 'Private key', 'ECDH', ['deriveKey']);
//   try {
//     const m = JSON.parse(dec8(fromB64(text)));
//     const epk = await importKey(JSON.stringify(m.epk), 'Ephemeral key', 'ECDH', []);
//     const pt = await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(m.iv) }, await aesFrom(priv, epk, 'decrypt'), fromB64(m.ct));
//     return dec8(pt);
//   } catch (e) { return fail('Decryption failed: wrong private key or invalid ciphertext.'); }
// }

// async function ecdsaGenerate(set) {
//   const kp = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
//   set('pub', await jwk(kp.publicKey)); set('priv', await jwk(kp.privateKey));
// }
// async function ecdsaRun(sign, text, c) {
//   const algo = { name: 'ECDSA', hash: 'SHA-256' };
//   if (sign) {
//     const priv = await importKey(c.priv, 'Private key', 'ECDSA', ['sign']);
//     return toB64(await subtle.sign(algo, priv, enc8(text)));
//   }
//   const pub = await importKey(c.pub, 'Public key', 'ECDSA', ['verify']);
//   if (!c.sig.trim()) fail('Paste the signature to verify.');
//   let ok = false;
//   try { ok = await subtle.verify(algo, pub, fromB64(c.sig), enc8(text)); } catch (e) { fail('Signature is not valid Base64.'); }
//   return ok ? 'VALID: the message was signed by the owner of this public key and has not been changed.'
//             : 'INVALID: the signature does not match this message and public key.';
// }

// // --- Diffie-Hellman with BigInt. Toy parameters: p = 2^127 - 1 (a Mersenne prime), g = 3. Real systems use 2048-bit+ primes. ---
// const DH_P = 2n ** 127n - 1n, DH_G = 3n;
// const modPow = (b, e, m) => { let r = 1n; b %= m; while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; };  // square-and-multiply
// const randBig = () => BigInt('0x' + [...crypto.getRandomValues(new Uint8Array(15))].map(x => x.toString(16).padStart(2, '0')).join('')) + 2n;
// function dhRun(_, __, c) {
//   let a, b;
//   try { a = BigInt(c.a); b = BigInt(c.b); } catch (e) { fail('Private keys must be whole numbers. Use "Generate random private keys".'); }
//   if (a < 2n || b < 2n) fail('Private keys must be at least 2.');
//   const A_pub = modPow(DH_G, a, DH_P), B_pub = modPow(DH_G, b, DH_P);   // public = g^private mod p
//   const sA = modPow(B_pub, a, DH_P), sB = modPow(A_pub, b, DH_P);       // shared = (other's public)^private mod p
//   return `Public parameters: p = 2^127 - 1 = ${DH_P}, g = ${DH_G}\n\nUser A public key (g^a mod p):\n${A_pub}\n\nUser B public key (g^b mod p):\n${B_pub}\n\n` +
//     `A computes B^a mod p:\n${sA}\n\nB computes A^b mod p:\n${sB}\n\nShared secrets match: ${sA === sB ? 'YES' : 'NO'}`;
// }

/* ---------- 5. ALGORITHM REGISTRY ----------
   Each entry: id, name, desc, fields (form inputs), run(isFirstMode, text, config), optional actions / modes / noInput. */
// const wrap = f => (isFirst, text, c) => f(isFirst, text, c);
const keyField = [{ id: 'key', label: 'Secret key', type: 'text', value: '', placeholder: 'Passphrase' }];
const cj = (id, name, desc) => ({ id, name, desc, fields: keyField /* , run: cryptoJsCipher(id === 'tdes' ? 'TripleDES' : name) */ });
const jwkPair = [
  { id: 'pub', label: 'Public key', type: 'textarea', rows: 4 },
  { id: 'priv', label: 'Private key', type: 'textarea', rows: 4 }];

const ALGOS = [
  { group: 'A. Classical ciphers', items: [
    { id: 'caesar', name: 'Caesar', desc: 'Shifts every letter by a fixed number of positions.',
      fields: [{ id: 'shift', label: 'Shift', type: 'text', value: '3' }] /* , run: wrap(caesar) */ },
    { id: 'affine', name: 'Affine', desc: 'C = (a*P + b) mod 26. Key a must be coprime with 26.',
      fields: [{ id: 'a', label: 'Key a', type: 'text', value: '5' }, { id: 'b', label: 'Key b', type: 'text', value: '8' }] /* , run: wrap(affine) */ },
    { id: 'vigenere', name: 'Vigenere', desc: 'Polyalphabetic substitution using a repeating keyword.',
      fields: [{ id: 'key', label: 'Keyword', type: 'text', value: 'LEMON' }] /* , run: wrap(vigenere) */ },
    { id: 'playfair', name: 'Playfair', desc: 'Digraph substitution using a 5x5 keyword square (J is merged into I). Output is uppercase; filler X letters stay after decryption.',
      fields: [{ id: 'key', label: 'Keyword', type: 'text', value: 'MONARCHY' }] /* , run: wrap(playfair) */ },
    { id: 'hill', name: 'Hill', desc: 'Matrix multiplication mod 26. Enter 4 numbers (2x2) or 9 numbers (3x3), row by row. Output is uppercase; padding X stays after decryption.',
      fields: [{ id: 'key', label: 'Key matrix', type: 'text', value: '3 3 2 5' }] /* , run: wrap(hill) */ }] },
  { group: 'B. Modern symmetric', items: [
    cj('AES', 'AES', 'AES with CryptoJS (CBC mode, key derived from the passphrase). Ciphertext is Base64.'),
    cj('DES', 'DES', 'DES, 56-bit key. Obsolete; included for study.'),
    cj('tdes', '3DES', 'Triple DES (TripleDES in CryptoJS).'),
    cj('RC4', 'RC4', 'Stream cipher. Used because CryptoJS does not include Blowfish or Twofish.'),
    cj('Rabbit', 'Rabbit', 'Stream cipher from the eSTREAM portfolio.'),
    { id: 'chacha', name: 'ChaCha20', desc: 'Hand-written RFC 8439 implementation. Key = SHA-256(passphrase); output is Base64(nonce + ciphertext).',
      fields: keyField /* , run: chachaRun */ }] },
  { group: 'C. Asymmetric', items: [
    { id: 'rsa', name: 'RSA', desc: 'Generate a key pair, encrypt with the public key, decrypt with the private key (JSEncrypt).',
      fields: [{ id: 'size', label: 'Key size (bits)', type: 'select', options: ['1024', '2048'], value: '1024' }, ...jwkPair],
      actions: [{ label: 'Generate key pair', fn: null /* rsaGenerate */ }] /* , run: rsaRun */ },
    { id: 'ecc', name: 'ECC (ECIES)', desc: 'P-256 key pair. Encryption uses an ephemeral ECDH key and AES-GCM (Web Crypto API). Keys are JWK JSON.',
      fields: jwkPair, actions: [{ label: 'Generate key pair', fn: null /* eccGenerate */ }] /* , run: eccRun */ },
    { id: 'dh', name: 'Diffie-Hellman', desc: 'Two users derive the same shared secret without sending it. Uses a small demo prime, not production strength.',
      noInput: true, modes: ['Compute'],
      fields: [{ id: 'a', label: 'User A private key', type: 'text', value: '' }, { id: 'b', label: 'User B private key', type: 'text', value: '' }],
      actions: [{ label: 'Generate random private keys', fn: null /* (set) => { set('a', randBig().toString()); set('b', randBig().toString()); } */ }]
      /* , run: dhRun */ },
    { id: 'ecdsa', name: 'ECDSA (signatures)', desc: 'Sign a message with the private key; verify with the public key. DSA is not offered by browsers, so ECDSA (P-256, SHA-256) is used.',
      modes: ['Sign', 'Verify'],
      fields: [...jwkPair, { id: 'sig', label: 'Signature (needed for Verify)', type: 'textarea', rows: 3 }],
      actions: [{ label: 'Generate key pair', fn: null /* ecdsaGenerate */ }] /* , run: ecdsaRun */ }] }
];

/* ---------- 6. UI ENGINE ---------- */
const $ = id => document.getElementById(id);
let current = ALGOS[0].items[0], modeIdx = 0;

// /** Read all current values of the config form into an object. */
// const readConfig = () => Object.fromEntries(current.fields.map(f => [f.id, $('f_' + f.id).value]));
// /** Write a value into a config field (used by key generators). */
// const setField = (id, v) => { $('f_' + id).value = v; };

function showError(msg) { $('error').textContent = msg || ''; }

function renderSidebar() {
  $('sidebar').innerHTML = ALGOS.map(g => `<div class="nav-group">${g.group}</div>` +
    g.items.map(i => `<button class="nav-item${i === current ? ' active' : ''}" data-id="${i.id}">${i.name}</button>`).join('')).join('');
  $('sidebar').querySelectorAll('.nav-item').forEach(b => b.onclick = () => {
    current = ALGOS.flatMap(g => g.items).find(i => i.id === b.dataset.id); modeIdx = 0; renderAlgo();
  });
}

function renderAlgo() {
  renderSidebar(); showError(''); $('output').value = '';
  $('algoName').textContent = current.name; $('algoDesc').textContent = current.desc;
  const modes = current.modes || ['Encrypt', 'Decrypt'];
  $('modeBar').innerHTML = modes.map((m, i) => `<button class="mode-btn${i === modeIdx ? ' active' : ''}" data-i="${i}">${m}</button>`).join('');
  $('modeBar').style.display = modes.length > 1 ? 'inline-flex' : 'none';
  $('modeBar').querySelectorAll('button').forEach(b => b.onclick = () => { modeIdx = +b.dataset.i; renderAlgo(); });
  $('run').textContent = modes[modeIdx];
  $('inputBox').style.display = current.noInput ? 'none' : 'block';
  // Build the dynamic configuration fields
  $('config').innerHTML = current.fields.map(f => {
    const label = `<label for="f_${f.id}" class="text-sm block mb-1">${f.label}</label>`;
    if (f.type === 'textarea') return label + `<textarea id="f_${f.id}" rows="${f.rows || 3}" class="field">${f.value || ''}</textarea>`;
    if (f.type === 'select') return label + `<select id="f_${f.id}" class="field">${f.options.map(o => `<option>${o}</option>`).join('')}</select>`;
    return label + `<input id="f_${f.id}" type="text" class="field" value="${f.value || ''}" placeholder="${f.placeholder || ''}">`;
  }).join('');
  $('actions').innerHTML = (current.actions || []).map((a, i) => `<button class="btn-light" data-a="${i}">${a.label}</button>`).join('');
//   $('actions').querySelectorAll('button').forEach(b => b.onclick = async () => {
//     showError('');
//     try { await current.actions[+b.dataset.a].fn(setField, readConfig()); } catch (e) { showError(e.message); }
//   });
}

// // Run the selected algorithm; any thrown error is shown as soft red text
// $('run').onclick = async () => {
//   showError(''); $('output').value = '';
//   const text = $('input').value;
//   if (!current.noInput && !text) return showError('Please enter some text first.');
//   try {
//     const result = await current.run(modeIdx === 0, text, readConfig());
//     $('output').value = result;
//   } catch (e) { showError(e.message || 'Something went wrong.'); }
// };

// // .txt upload (read client-side with FileReader)
// $('upload').onchange = e => {
//   const f = e.target.files[0]; if (!f) return;
//   const r = new FileReader(); r.onload = () => { $('input').value = r.result; }; r.readAsText(f); e.target.value = '';
// };

// $('copy').onclick = async () => {
//   if (!$('output').value) return showError('Nothing to copy yet.');
//   try { await navigator.clipboard.writeText($('output').value); $('copy').textContent = 'Copied'; }
//   catch (e) { $('output').select(); document.execCommand('copy'); $('copy').textContent = 'Copied'; }
//   setTimeout(() => { $('copy').textContent = 'Copy to clipboard'; }, 1500);
// };

// $('download').onclick = () => {
//   if (!$('output').value) return showError('Nothing to download yet.');
//   const a = document.createElement('a');
//   a.href = URL.createObjectURL(new Blob([$('output').value], { type: 'text/plain' }));
//   a.download = `${current.id}-output.txt`; a.click(); URL.revokeObjectURL(a.href);
// };

renderAlgo();
