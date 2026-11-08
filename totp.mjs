/** RFC 6238 TOTP utilities. All processing is local to the browser. */
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function normalizeBase32(value) {
  if (typeof value !== 'string' || value.length > 4096) throw new Error('Secret key is too long.');
  const cleaned = value.replace(/[\s-]/g, '').toUpperCase();
  if (!cleaned) throw new Error('Enter a Base32 secret key first.');
  const match = /^([A-Z2-7]+)(=*)$/.exec(cleaned);
  if (!match) throw new Error('The secret key must contain Base32 letters A–Z and numbers 2–7.');
  const chars = match[1];
  if (![0, 2, 4, 5, 7].includes(chars.length % 8)) throw new Error('Invalid Base32 secret length.');
  if (chars.length % 8 === 0 && match[2].length) throw new Error('Invalid Base32 padding.');
  if (match[2].length && (chars.length + match[2].length) % 8 !== 0) throw new Error('Invalid Base32 padding.');
  if (chars.length < 2) throw new Error('Secret key is too short.');
  return chars;
}

export function decodeBase32(value) {
  const clean = normalizeBase32(value);
  let bits = 0, buffer = 0;
  const bytes = [];
  for (const char of clean) {
    buffer = (buffer << 5) | B32.indexOf(char);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >>> bits) & 255);
    }
    buffer &= (1 << bits) - 1;
  }
  if (buffer !== 0) throw new Error('Invalid nonzero Base32 trailing bits.');
  return new Uint8Array(bytes);
}

export function validateOptions({ algorithm, digits, period }) {
  if (!['SHA1', 'SHA256', 'SHA512'].includes(algorithm)) throw new Error('Unsupported algorithm.');
  if (!Number.isInteger(digits) || digits < 6 || digits > 8) throw new Error('Use 6, 7, or 8 digits.');
  if (!Number.isInteger(period) || period < 5 || period > 300) throw new Error('Period must be 5–300 seconds.');
}

export function parseOtpAuth(input) {
  if (typeof input !== 'string' || input.length > 4096) throw new Error('Provisioning URL is too long.');
  const url = new URL(input.trim());
  if (url.protocol !== 'otpauth:' || url.hostname.toLowerCase() !== 'totp') {
    throw new Error('Only otpauth://totp provisioning links are supported.');
  }
  if (url.username || url.password || url.port || url.hash) throw new Error('Unsupported provisioning link format.');
  const secret = normalizeBase32(url.searchParams.get('secret') || '');
  const algorithm = (url.searchParams.get('algorithm') || 'SHA1').toUpperCase().replace(/-/g, '');
  const digits = Number(url.searchParams.get('digits') || 6);
  const period = Number(url.searchParams.get('period') || 30);
  validateOptions({ algorithm, digits, period });
  const label = decodeURIComponent(url.pathname.slice(1));
  const colon = label.indexOf(':');
  const account = colon === -1 ? label : label.slice(colon + 1);
  const issuer = url.searchParams.get('issuer') || (colon === -1 ? '' : label.slice(0, colon));
  return { secret, account: account.slice(0, 120), issuer: issuer.slice(0, 120), algorithm, digits, period };
}

export function makeOtpAuthURL({ secret, account = '', issuer = '', algorithm = 'SHA1', digits = 6, period = 30 }) {
  const key = normalizeBase32(secret);
  validateOptions({ algorithm, digits, period });
  const a = String(account).trim().slice(0, 120) || 'My Account';
  const i = String(issuer).trim().slice(0, 120);
  const label = i ? i + ':' + a : a;
  const params = new URLSearchParams({ secret: key });
  if (i) params.set('issuer', i);
  params.set('algorithm', algorithm);
  params.set('digits', String(digits));
  params.set('period', String(period));
  return 'otpauth://totp/' + encodeURIComponent(label) + '?' + params.toString();
}

export async function generateTOTP({ secret, algorithm = 'SHA1', digits = 6, period = 30 }, epochMillis = Date.now()) {
  validateOptions({ algorithm, digits, period });
  if (!Number.isFinite(epochMillis) || epochMillis < 0) throw new Error('Invalid clock time.');
  if (!globalThis.crypto?.subtle) throw new Error('Secure Web Crypto is unavailable. Use HTTPS or localhost.');
  const key = decodeBase32(secret);
  const counter = BigInt(Math.floor(epochMillis / 1000 / period));
  const bytes = new Uint8Array(8);
  for (let idx = 7, n = counter; idx >= 0; idx--, n >>= 8n) bytes[idx] = Number(n & 255n);
  const hash = algorithm === 'SHA1' ? 'SHA-1' : algorithm === 'SHA256' ? 'SHA-256' : 'SHA-512';
  const hmacKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash }, false, ['sign']);
  const result = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, bytes));
  const off = result[result.length - 1] & 15;
  const num = ((result[off] & 127) << 24) | (result[off + 1] << 16) |
              (result[off + 2] << 8) | result[off + 3];
  return String((num >>> 0) % 10 ** digits).padStart(digits, '0');
}
