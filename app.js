const files = { host: null, image: null };
const outputs = [];
const $ = selector => document.querySelector(selector);

for (const kind of ['host', 'image']) {
  const input = $(`#${kind}-file`);
  const zone = $(`#${kind}-zone`);
  input.addEventListener('change', () => setFile(kind, input.files[0]));
  zone.addEventListener('dragover', event => {
    event.preventDefault();
    zone.classList.add('drag');
  });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag'));
  zone.addEventListener('drop', event => {
    event.preventDefault();
    zone.classList.remove('drag');
    setFile(kind, event.dataTransfer.files[0]);
  });
}

function setFile(kind, file) {
  if (!file) return;
  if (!file.name.toLowerCase().endsWith('.csv')) {
    alert('Please choose a CSV file.');
    return;
  }
  files[kind] = file;
  $(`#${kind}-name`).textContent = file.name;
  $('#run').disabled = !(files.host || files.image);
}

function parseCSV(text) {
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;
  text = text.replace(/^\uFEFF/, '');

  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (quoted) {
      if (char === '"' && text[i + 1] === '"') {
        field += '"';
        i++;
      } else if (char === '"') {
        quoted = false;
      } else {
        field += char;
      }
    } else if (char === '"') {
      quoted = true;
    } else if (char === ',') {
      row.push(field);
      field = '';
    } else if (char === '\n') {
      row.push(field.replace(/\r$/, ''));
      rows.push(row);
      row = [];
      field = '';
    } else {
      field += char;
    }
  }

  if (field.length || row.length) {
    row.push(field.replace(/\r$/, ''));
    rows.push(row);
  }
  return rows.filter(current => current.some(value => value.trim()));
}

const cryptoSpecificRules = [
  {
    label: 'Weak or unsafe cryptography',
    pattern: /\b(?:weak|insecure|deprecated|obsolete|broken|unsafe)\s+(?:cipher(?:s)?|cryptograph(?:y|ic|ically)?|hash(?:ing)?|key(?:\s+(?:length|size))?|algorithm|random(?:ness)?|TLS|SSL|protocol)\b/i
  },
  {
    label: 'Weak or unsafe cryptography',
    pattern: /\b(?:cipher|cryptograph(?:y|ic|ically)?|hash(?:ing)?|key(?:\s+(?:length|size))?|algorithm|random(?:ness)?|TLS|SSL|protocol)\s+(?:(?:is|are|was|were)\s+)?(?:weak|insecure|deprecated|obsolete|broken|unsafe)\b/i
  },
  {
    label: 'Legacy TLS/SSL version',
    pattern: /\b(?:SSL\s*v?(?:2(?:\.0)?|3(?:\.0)?)|TLS\s*v?1\.[01])\b/i
  },
  {
    label: 'Weak or legacy algorithm',
    pattern: /\b(?:MD2|MD4|MD5|SHA-?1|DES|3DES|RC2|RC4|Blowfish|export[- ]grade|NULL cipher)\b/i
  },
  {
    label: 'Cryptography-related CWE',
    pattern: /\bCWE-(?:295|326|327|330)\b/i
  }
];

const cryptoContextRules = [
  {
    label: 'Cryptography context term',
    pattern: /\b(?:cryptograph\w*|encrypt(?:ion|ed|ing)?|decrypt(?:ion|ed|ing)?|certificates?|private key|public key|key management|key rotation)\b/i
  }
];

const cryptoLibraryPattern = /\b(?:OpenSSL|libssl\d*|libcrypto\d*|BoringSSL|wolfSSL|GnuTLS|mbedTLS|cryptsetup|libgcrypt|libsodium|bcrypt|Bouncy\s?Castle)\b/i;

const miningRules = [
  {
    label: 'Cryptocurrency mining indicator',
    pattern: /\b(?:crypto(?:currency)?[\s-]*min(?:er|ing)|coin[- ]?miner|mining pool|stratum(?:\+tcp)?)\b/i
  },
  {
    label: 'Known mining tool',
    pattern: /\b(?:xmrig|kinsing|kdevtmpfsi|cpuminer|minerd|ethminer|t-rex(?:\s+miner)?|nicehash)\b/i
  },
  {
    label: 'Coin linked to mining',
    pattern: /\b(?:monero|bitcoin|ethereum)\s+(?:miner|mining|pool)\b/i
  }
];

function classifyColumns(header) {
  const findingIndexes = [];
  const packageIndexes = [];

  header.forEach((name, index) => {
    const normalized = name.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (/(finding|vulnerability|vuln|issue|alert|policy|rule|description|title|details|detail|cause|risk|recommendation|remediation|evidence|check|control)/.test(normalized)) {
      findingIndexes.push(index);
    }
    if (/(package|component|library|libraries|software|technology|product|artifact)/.test(normalized)) {
      packageIndexes.push(index);
    }
  });

  return { findingIndexes, packageIndexes };
}

function textAt(row, indexes) {
  return indexes.map(index => row[index] || '').filter(Boolean).join(' ');
}

function collectRuleMatches(text, rules, reasons) {
  for (const rule of rules) {
    const match = text.match(rule.pattern);
    if (match) reasons.push(`${rule.label}: “${match[0]}”`);
  }
}

function matchReasons(row, columns, enabled) {
  const allText = row.join(' ');
  const findingText = columns.findingIndexes.length
    ? textAt(row, columns.findingIndexes)
    : allText;
  const packageText = columns.packageIndexes.length
    ? textAt(row, columns.packageIndexes)
    : findingText;
  const reasons = [];

  if (enabled.includes('cryptography')) {
    collectRuleMatches(allText, cryptoSpecificRules, reasons);
    collectRuleMatches(findingText, cryptoContextRules, reasons);

    // Package fields help find crypto libraries without treating every mention in
    // arbitrary asset metadata as a library finding.
    const libraryText = packageText || findingText;
    const libraryMatch = libraryText.match(cryptoLibraryPattern);
    if (libraryMatch) reasons.push(`Crypto library/package reference: “${libraryMatch[0]}”`);
  }

  if (enabled.includes('mining')) {
    collectRuleMatches(allText, miningRules, reasons);
  }

  return [...new Set(reasons)].slice(0, 4);
}

$('#run').addEventListener('click', async () => {
  const enabled = ['cryptography', 'mining'].filter(kind => $(`#${kind}`).checked);
  if (!enabled.length) {
    alert('Select at least one crypto category.');
    return;
  }

  outputs.length = 0;
  for (const kind of ['host', 'image']) {
    if (!files[kind]) continue;
    try {
      const rows = parseCSV(await files[kind].text());
      if (rows.length < 1) throw Error('No header row found');
      const header = rows[0];
      const columns = classifyColumns(header);
      const matches = [];
      for (let rowIndex = 1; rowIndex < rows.length; rowIndex++) {
        const row = rows[rowIndex];
        const reasons = matchReasons(row, columns, enabled);
        if (reasons.length) matches.push({ row, reasons });
      }
      outputs.push({ kind, name: files[kind].name, header, matches, total: rows.length - 1 });
    } catch (error) {
      alert(`${files[kind].name}: ${error.message}`);
      return;
    }
  }
  render();
});

function esc(value) {
  return String(value).replace(/[&<>"']/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[char]);
}

function render() {
  const totalMatches = outputs.reduce((count, output) => count + output.matches.length, 0);
  const reportsWithMatches = outputs.filter(output => output.matches.length).length;
  $('#stats').innerHTML = `<div class="stat"><strong>${totalMatches}</strong><span>MATCHING ROWS</span></div><div class="stat"><strong>${outputs.reduce((count, output) => count + output.total, 0)}</strong><span>ROWS SCANNED</span></div><div class="stat"><strong>${reportsWithMatches} / ${outputs.length}</strong><span>REPORTS WITH MATCHES</span></div>`;
  $('#result-cards').innerHTML = outputs.map(output => `<div class="result-card"><div class="result-head"><span>${output.kind === 'host' ? 'Host' : 'Image'} report</span><small>${output.matches.length} / ${output.total} matches · ${esc(output.name)}</small></div>${output.matches.length ? `<div class="table-wrap"><table><thead><tr>${output.header.map(value => `<th title="${esc(value)}">${esc(value)}</th>`).join('')}<th>Why matched</th></tr></thead><tbody>${output.matches.slice(0, 50).map(({ row, reasons }) => `<tr>${output.header.map((_, index) => `<td title="${esc(row[index] || '')}">${esc(row[index] || '')}</td>`).join('')}<td class="reason-cell" title="${esc(reasons.join('; '))}">${esc(reasons.join('; '))}</td></tr>`).join('')}</tbody></table></div>${output.matches.length > 50 ? '<div class="empty">Showing first 50 rows. Download CSV for the complete result.</div>' : ''}` : '<div class="empty">No selected indicators found in this report.</div>'}</div>`).join('');
  $('#results').hidden = false;
  $('#results').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function csvCell(value) {
  return `"${String(value ?? '').replace(/"/g, '""')}"`;
}

$('#download-all').addEventListener('click', () => {
  const rows = [];
  for (const output of outputs) {
    rows.push([`# ${output.kind.toUpperCase()} REPORT — ${output.name}`]);
    rows.push([...output.header, 'CryptoLens match reason']);
    rows.push(...output.matches.map(({ row, reasons }) => [...row, reasons.join('; ')]));
  }
  const blob = new Blob(['\ufeff' + rows.map(row => row.map(csvCell).join(',')).join('\r\n')], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'cryptolens-findings.csv';
  link.click();
  URL.revokeObjectURL(url);
});
