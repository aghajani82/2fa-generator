import { test } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { normalizeBase32, decodeBase32, generateTOTP, makeOtpAuthURL, parseOtpAuth } from '../totp.mjs';
globalThis.crypto ??= webcrypto;
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function encodeBase32(bytes) {
  let bits = 0, buffer = 0, out = '';
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += B32[(buffer >>> bits) & 31];
    }
    buffer &= (1 << bits) - 1;
  }
  if (bits) out += B32[(buffer << (5 - bits)) & 31];
  return out;
}
const keys = {
  SHA1: encodeBase32(new TextEncoder().encode('12345678901234567890')),
  SHA256: encodeBase32(new TextEncoder().encode('12345678901234567890123456789012')),
  SHA512: encodeBase32(new TextEncoder().encode('1234567890123456789012345678901234567890123456789012345678901234')),
};
const vectors = [
  [59, '94287082', '46119246', '90693936'],
  [1111111109, '07081804', '68084774', '25091201'],
  [1111111111, '14050471', '67062674', '99943326'],
  [1234567890, '89005924', '91819424', '93441116'],
  [2000000000, '69279037', '90698825', '38618901'],
  [20000000000, '65353130', '77737706', '47863826']
];
test('All 18 official RFC 6238 Appendix B TOTP test vectors', async () => {
  for (const [time, ...expected] of vectors) {
    for (const [index, algorithm] of ['SHA1','SHA256','SHA512'].entries()) {
      assert.equal(await generateTOTP({ secret: keys[algorithm], algorithm, digits:8, period:30 }, time * 1000), expected[index]);
    }
  }
});
test('Base32 accepts spaces, hyphens, lowercase and optional padding', () => {
  assert.equal(normalizeBase32(' jbsw-y3dp ehpk3pxp '), 'JBSWY3DPEHPK3PXP');
  assert.equal(Buffer.from(decodeBase32('MZXW6===')).toString(), 'foo');
  assert.throws(() => decodeBase32('MZXW7==='), /trailing bits/);
  for (const bad of ['J!', 'M', 'ABC', 'MZXW6=', 'MY======A', '']) assert.throws(() => normalizeBase32(bad));
});
test('otpauth link import/export and invalid algorithms', () => {
  const input = { secret:keys.SHA1, issuer:'Hetzner Cloud', account:'name+test@example.com', algorithm:'SHA256', digits:8, period:60 };
  assert.deepEqual(parseOtpAuth(makeOtpAuthURL(input)), input);
  assert.throws(() => parseOtpAuth('otpauth://hotp/X?secret=JBSWY3DPEHPK3PXP'));
  assert.throws(() => parseOtpAuth('otpauth://totp/X?secret=JBSWY3DPEHPK3PXP&algorithm=MD5'));
});
test('6-digit codes retain leading zeroes', async () => {
  assert.equal(await generateTOTP({ secret:keys.SHA1, algorithm:'SHA1', digits:6, period:30 }, 1111111109 * 1000), '081804');
});
