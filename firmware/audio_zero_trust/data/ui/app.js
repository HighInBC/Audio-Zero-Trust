const rawOut = document.getElementById('rawOut');
const applyResult = document.getElementById('applyResult');

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value ?? '-';
}

function buildUnsignedConfig() {
  const deviceLabel = document.getElementById('cfgDeviceLabel')?.value?.trim() || 'device';
  const wifiSsid = document.getElementById('cfgWifiSsid')?.value?.trim() || '';
  const wifiPass = document.getElementById('cfgWifiPass')?.value || '';
  const adminFp = document.getElementById('cfgAdminFp')?.value?.trim() || '';
  const adminPem = document.getElementById('cfgAdminPem')?.value || '';

  const cfg = {
    config_version: 1,
    device_label: deviceLabel,
    admin_key: {
      alg: 'ed25519',
      public_key_b64: adminPem,
      fingerprint_alg: 'sha256-raw-ed25519-pub',
      fingerprint_hex: adminFp,
    },
    wifi: {
      ssid: wifiSsid,
      password: wifiPass,
    },
    time: {
      server: 'pool.ntp.org',
    },
    audio: {
      sample_rate_hz: 16000,
      channels: 1,
      sample_width_bytes: 2,
    },
  };

  const unsignedEl = document.getElementById('unsignedJson');
  if (unsignedEl) unsignedEl.value = JSON.stringify(cfg, null, 2);
  renderCliHint();
  return cfg;
}

function renderCliHint() {
  const hint = document.getElementById('cliHint');
  if (!hint) return;
  const host = window.location.hostname || '192.168.1.113';
  const base = `http://${host}:8080`;
  hint.textContent = [
    '# 1) Save unsigned JSON from this page to unsigned_config.json',
    '# 2) One-command sign + apply + state check:',
    `python3 client/tools/azt_tool.py apply-config --host ${host} --port 8080 --in unsigned_config.json --key admin_private_key.pem`,
    '',
    '# Optional: only sign to a file',
    'python3 client/tools/azt_tool.py sign-config --in unsigned_config.json --key admin_private_key.pem --out signed_config.json',
    '',
    '# Optional manual verify:',
    `curl -sS ${base}/api/v0/config/state`,
  ].join('\n');
}

function downloadUnsignedJson() {
  const unsignedEl = document.getElementById('unsignedJson');
  if (!unsignedEl || !unsignedEl.value?.trim()) buildUnsignedConfig();
  const body = unsignedEl?.value || '{}';
  const blob = new Blob([body], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'unsigned_config.json';
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(a.href);
}

async function loadState() {
  try {
    const r = await fetch('/api/v0/config/state');
    const j = await r.json();

    setText('deviceLabel', j.device_label || '-');
    setText('deviceState', j.state || '-');
    setText('signedReady', String(j.signed_config_ready));
    setText('wifiConfigured', String(j.wifi_configured));
    setText('wifiSsid', j.wifi_ssid || '-');
    setText('wifiSource', j.wifi_last_connect_source || '-');
    setText('wifiStatus', String(j.wifi_last_status));
    setText('adminFp', j.admin_fingerprint_hex || '-');
    setText('devSignFp', j.device_sign_fingerprint_hex || '-');
    setText('certSerial', j.device_certificate_serial || '(none)');

    const fpInput = document.getElementById('cfgAdminFp');
    if (fpInput && !fpInput.value) fpInput.value = j.admin_fingerprint_hex || '';
    const labelInput = document.getElementById('cfgDeviceLabel');
    if (labelInput && !labelInput.value) labelInput.value = j.device_label || '';
    const ssidInput = document.getElementById('cfgWifiSsid');
    if (ssidInput && !ssidInput.value) ssidInput.value = j.wifi_ssid || '';

    rawOut.textContent = JSON.stringify(j, null, 2);
  } catch (e) {
    rawOut.textContent = String(e);
  }
}

function shQuote(s) {
  const v = String(s ?? '');
  if (!v) return "''";
  return `'${v.replace(/'/g, `'"'"'`)}'`;
}

function buildCertificationCommand() {
  const serial = document.getElementById('certSerialInput')?.value?.trim() || '';
  const issueId = document.getElementById('certIssueId')?.value?.trim() || '';
  const title = document.getElementById('certTitle')?.value?.trim() || '';
  const expected = document.getElementById('certExpected')?.value?.trim() || '';
  const actual = document.getElementById('certActual')?.value?.trim() || '';
  const repro = (document.getElementById('certRepro')?.value || '').split('\n').map(s => s.trim()).filter(Boolean);
  const evidence = (document.getElementById('certEvidence')?.value || '').split('\n').map(s => s.trim()).filter(Boolean);
  const meta = (document.getElementById('certMeta')?.value || '').split('\n').map(s => s.trim()).filter(Boolean);

  const host = window.location.hostname || '192.168.1.113';
  const parts = [
    'python3 client/tools/azt_tool.py certify-issue',
    '--host', shQuote(host),
    '--port', '8080',
    '--serial', shQuote(serial || 'SERIAL_HERE'),
    '--issue-id', shQuote(issueId || 'ISSUE-ID'),
    '--title', shQuote(title || 'Issue title'),
  ];

  if (expected) parts.push('--expected', shQuote(expected));
  if (actual) parts.push('--actual', shQuote(actual));
  repro.forEach(v => parts.push('--repro', shQuote(v)));
  evidence.forEach(v => parts.push('--evidence', shQuote(v)));
  meta.forEach(v => parts.push('--meta', shQuote(v)));

  parts.push('--key', shQuote('admin_private_key.pem'));
  parts.push('--out', shQuote('issue_certification.json'));

  const cmd = parts.join(' ');
  const out = document.getElementById('certCmdOut');
  if (out) out.textContent = cmd;
  return cmd;
}

async function copyCertificationCommand() {
  const cmd = buildCertificationCommand();
  try {
    await navigator.clipboard.writeText(cmd);
  } catch {
    // no-op
  }
}

async function rebootDevice() {
  const ok = confirm('Reboot device now?');
  if (!ok) return;
  try {
    const r = await fetch('/api/v0/device/reboot', { method: 'POST' });
    const t = await r.text();
    rawOut.textContent = `Reboot request HTTP ${r.status}\n${t}\n\nDevice may take a few seconds to come back.`;
  } catch (e) {
    rawOut.textContent = `Reboot request failed: ${String(e)}`;
  }
}

async function applySignedConfig() {
  const fi = document.getElementById('signedUpload');
  const file = fi?.files?.[0];
  if (!file) {
    applyResult.textContent = 'Select signed_config.json first.';
    return;
  }

  try {
    const text = await file.text();
    const payload = JSON.parse(text);

    const r = await fetch('/api/v0/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const body = await r.text();

    let parsed = body;
    try { parsed = JSON.parse(body); } catch {}

    applyResult.textContent = JSON.stringify({
      http_status: r.status,
      response: parsed,
    }, null, 2);

    await loadState();
  } catch (e) {
    applyResult.textContent = `Apply failed: ${String(e)}`;
  }
}

document.getElementById('refreshBtn')?.addEventListener('click', loadState);
document.getElementById('rebootBtn')?.addEventListener('click', rebootDevice);
document.getElementById('buildUnsignedBtn')?.addEventListener('click', buildUnsignedConfig);
document.getElementById('downloadUnsignedBtn')?.addEventListener('click', downloadUnsignedJson);
document.getElementById('applySignedBtn')?.addEventListener('click', applySignedConfig);
document.getElementById('buildCertCmdBtn')?.addEventListener('click', buildCertificationCommand);
document.getElementById('copyCertCmdBtn')?.addEventListener('click', copyCertificationCommand);

renderCliHint();
buildUnsignedConfig();
buildCertificationCommand();
loadState();
