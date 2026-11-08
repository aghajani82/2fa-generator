import { normalizeBase32, parseOtpAuth, makeOtpAuthURL, generateTOTP, validateOptions } from './totp.mjs';
const $ = id => document.getElementById(id);
const form = $('generator'), input = $('secret'), codeEl = $('code');
const errorEl = $('error'), statusEl = $('status'), qrToggle = $('qrToggle'), qrPanel = $('qrPanel');
let active = null, lastStep = null, generation = 0, interval = null, statusTimer = null;

function message(value = '') {
  statusEl.textContent = value;
  clearTimeout(statusTimer);
  if (value) statusTimer = setTimeout(() => { statusEl.textContent = ''; }, 4000);
}
function error(value = '') {
  errorEl.textContent = value;
  errorEl.hidden = !value;
}
function settings() {
  const data = {
    algorithm: $('algorithm').value,
    digits: Number($('digits').value),
    period: Number($('period').value),
    issuer: $('issuer').value,
    account: $('account').value,
  };
  validateOptions(data);
  return data;
}
function hideQR() {
  qrPanel.hidden = true;
  qrToggle.setAttribute('aria-expanded', 'false');
  $('qrLabel').textContent = 'Show QR code';
  $('chevron').textContent = '⌄';
}
function maskAndReset() {
  active = null;
  lastStep = null;
  generation++;
  clearInterval(interval);
  interval = null;
  codeEl.textContent = '— — — — — —';
  $('seconds').textContent = '30';
  $('countdownRing').style.setProperty('--progress', '100%');
  $('copy').disabled = true;
  qrToggle.disabled = true;
  hideQR();
  $('qr').replaceChildren();
}
function updateTime() {
  if (!active) return;
  const now = Date.now(), periodMs = active.period * 1000;
  const step = Math.floor(now / periodMs);
  const left = periodMs - now % periodMs;
  $('seconds').textContent = String(Math.max(1, Math.ceil(left / 1000)));
  $('countdownRing').style.setProperty('--progress', String(left / periodMs * 100) + '%');
  if (step === lastStep) return;
  lastStep = step;
  const serial = ++generation;
  generateTOTP(active, now).then(code => {
    if (serial !== generation || !active || step !== Math.floor(Date.now() / periodMs)) return;
    codeEl.textContent = code.length === 6 ? code.slice(0, 3) + ' ' + code.slice(3) : code;
    $('copy').disabled = false;
  }).catch(e => {
    if (serial === generation) { error(e.message); maskAndReset(); }
  });
}
function qrRender() {
  if (!active) return;
  if (typeof globalThis.QRCode !== 'function') throw new Error('Local QR generator could not be loaded.');
  const target = $('qr');
  target.replaceChildren();
  new globalThis.QRCode(target, {
    text: makeOtpAuthURL(active),
    width: 252,
    height: 252,
    colorDark: '#070b16',
    colorLight: '#ffffff',
    correctLevel: globalThis.QRCode.CorrectLevel.M
  });
}
form.addEventListener('submit', e => {
  e.preventDefault();
  maskAndReset(); error(); message();
  try {
    const value = input.value.trim();
    let config = settings();
    if (/^otpauth:/i.test(value)) {
      const parsed = parseOtpAuth(value);
      config = { ...config, ...parsed };
      input.value = parsed.secret;
      $('algorithm').value = parsed.algorithm;
      $('digits').value = String(parsed.digits);
      $('period').value = String(parsed.period);
      $('issuer').value = parsed.issuer;
      $('account').value = parsed.account;
      message('TOTP setup link imported locally.');
    } else config.secret = normalizeBase32(value);
    active = config;
    qrToggle.disabled = false;
    updateTime();
    interval = setInterval(updateTime, 250);
  } catch (e) { error(e.message); maskAndReset(); }
});
qrToggle.addEventListener('click', () => {
  if (!active) return;
  if (!qrPanel.hidden) {
    hideQR();
    $('qr').replaceChildren();
    return;
  }
  try {
    qrRender();
    qrPanel.hidden = false;
    qrToggle.setAttribute('aria-expanded', 'true');
    $('qrLabel').textContent = 'Hide QR code';
    $('chevron').textContent = '⌃';
  } catch (e) {
    error(e.message);
    hideQR();
  }
});
$('copy').addEventListener('click', async () => {
  if (!active || $('copy').disabled) return;
  const current = codeEl.textContent.replace(/\s/g, '');
  try {
    await navigator.clipboard.writeText(current);
    message('Code copied to clipboard.');
  } catch {
    message('Clipboard access denied. Select and copy the code manually.');
  }
});
$('reveal').addEventListener('click', () => {
  const visible = input.type === 'text';
  input.type = visible ? 'password' : 'text';
  $('reveal').textContent = visible ? 'Show' : 'Hide';
  $('reveal').setAttribute('aria-label', visible ? 'Show secret key' : 'Hide secret key');
});
$('clear').addEventListener('click', () => {
  maskAndReset(); error(); message();
  input.value = '';
  input.type = 'password';
  $('reveal').textContent = 'Show';
  $('reveal').setAttribute('aria-label', 'Show secret key');
  $('algorithm').value = 'SHA1';
  $('digits').value = '6';
  $('period').value = '30';
  $('issuer').value = '';
  $('account').value = '';
  input.focus();
});
for (const el of [input, $('algorithm'), $('digits'), $('period'), $('issuer'), $('account')]) {
  el.addEventListener('input', () => {
    if (active) {
      maskAndReset();
      message('Settings changed. Select Generate to refresh.');
    }
    error();
  });
}
document.addEventListener('visibilitychange', () => { if (!document.hidden) updateTime(); });
window.addEventListener('pagehide', () => { maskAndReset(); input.value = ''; });
