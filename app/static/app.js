const form = document.querySelector('#scan-form');
const submitButton = document.querySelector('#submit-button');
const errorBox = document.querySelector('#error');
const results = document.querySelector('#results');
const features = document.querySelector('#empty-features');
const actionLabels = {
  STRIPPED_HIDDEN_CSS_ELEMENTS: 'Removed visually hidden elements',
  REMOVED_INVISIBLE_UNICODE_CHARS: 'Removed invisible Unicode characters',
  FLAGGED_PROMPT_INJECTION_KEYWORDS: 'Flagged prompt-injection language',
  FLAGGED_ML_PROMPT_INJECTION: 'Flagged content identified by the ML classifier',
};

const MAX_BATCH = 10;
const batchSummary = document.querySelector('#batch-summary');
const detailArea = document.querySelector('#detail-area');

function currentMode() {
  return document.querySelector('input[name="scan-mode"]:checked').value;
}

function setLoading(loading) {
  submitButton.disabled = loading;
  document.querySelectorAll('input[name="scan-mode"]').forEach(radio => { radio.disabled = loading; });
  submitButton.classList.toggle('loading', loading);
  const batch = currentMode() === 'batch';
  submitButton.querySelector('.button-label').textContent = loading ? 'Inspecting…' : (batch ? 'Scan batch' : 'Scan page');
}

function resetResults() {
  results.hidden = true;
  batchSummary.hidden = true;
  detailArea.hidden = false;
  document.querySelector('#batch-list').replaceChildren();
  document.querySelector('#batch-counts').textContent = '';
  document.querySelector('#batch-detail-note').textContent = '';
  document.querySelector('#batch-raw').textContent = '';
  document.querySelector('#raw-output').textContent = '';
  document.querySelector('#formatted-text').replaceChildren();
  errorBox.hidden = true;
  features.hidden = false;
}

function formatDetail(detail, status) {
  if (typeof detail === 'string' && detail) return detail;
  if (Array.isArray(detail) && detail.length) {
    return detail.map(entry => {
      if (typeof entry === 'string') return entry;
      const msg = typeof entry?.msg === 'string' ? entry.msg : 'Invalid value';
      const loc = Array.isArray(entry?.loc)
        ? entry.loc.filter(part => part !== 'body').map(String).join('.')
        : '';
      return loc ? `${loc}: ${msg}` : msg;
    }).join('; ');
  }
  return `Request failed with status ${status}`;
}

function applyMode() {
  resetResults();
  const batch = currentMode() === 'batch';
  document.querySelector('#batch-field').hidden = !batch;
  document.querySelector('#single-field').hidden = batch;
  document.querySelector('#url-label').hidden = batch;
  document.querySelector('#url').required = !batch;
  submitButton.querySelector('.button-label').textContent = batch ? 'Scan batch' : 'Scan page';
}
document.querySelectorAll('input[name="scan-mode"]').forEach(radio => radio.addEventListener('change', applyMode));

function parseBatchUrls() {
  const urls = document.querySelector('#batch-urls').value.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
  if (!urls.length) throw new Error('Enter at least one URL.');
  if (urls.length > MAX_BATCH) throw new Error(`Batch scans support at most ${MAX_BATCH} URLs; you entered ${urls.length}.`);
  urls.forEach((value, index) => {
    let parsed;
    try { parsed = new URL(value); } catch { parsed = null; }
    if (!parsed || !['http:', 'https:'].includes(parsed.protocol)) {
      throw new Error(`Line ${index + 1} is not a valid http(s) URL.`);
    }
  });
  return urls;
}

function addAuditItem(container, title, detail, snippet, finding = false) {
  const item = document.createElement('div');
  item.className = `audit-item${finding ? ' finding-item' : ''}`;
  const strong = document.createElement('strong');
  strong.textContent = title;
  item.appendChild(strong);
  if (detail) item.appendChild(document.createTextNode(detail));
  if (snippet) {
    const code = document.createElement('code');
    code.textContent = snippet;
    item.appendChild(code);
  }
  container.appendChild(item);
}

function normalizedFlaggedRanges(findings, textLength) {
  const ranges = findings
    .filter(item => Number.isInteger(item.text_start) && Number.isInteger(item.text_end))
    .map(item => ({ start: item.text_start, end: item.text_end }))
    .filter(range => range.start >= 0 && range.start < range.end && range.end <= textLength)
    .sort((left, right) => left.start - right.start || left.end - right.end);

  return ranges.reduce((merged, range) => {
    const previous = merged[merged.length - 1];
    if (previous && range.start <= previous.end) {
      previous.end = Math.max(previous.end, range.end);
    } else {
      merged.push(range);
    }
    return merged;
  }, []);
}

function appendHighlightedText(container, text, textOffset, ranges) {
  let cursor = 0;
  ranges.forEach(range => {
    const start = Math.max(0, range.start - textOffset);
    const end = Math.min(text.length, range.end - textOffset);
    if (start >= end || end <= cursor) return;
    if (start > cursor) container.appendChild(document.createTextNode(text.slice(cursor, start)));
    const highlight = document.createElement('mark');
    highlight.className = 'flagged-text';
    highlight.title = 'Potential prompt-injection content';
    highlight.textContent = text.slice(Math.max(cursor, start), end);
    container.appendChild(highlight);
    cursor = end;
  });
  if (cursor < text.length) container.appendChild(document.createTextNode(text.slice(cursor)));
}

function renderFormattedText(text, findings) {
  const container = document.querySelector('#formatted-text');
  container.replaceChildren();
  if (!text.trim()) {
    const empty = document.createElement('p');
    empty.className = 'empty-output';
    empty.textContent = 'No readable text was returned.';
    container.appendChild(empty);
    return;
  }

  // Keep the page's paragraph boundaries while inserting content as text only,
  // never as executable HTML from the untrusted source.
  const ranges = normalizedFlaggedRanges(findings, text.length);
  const blocks = text.split(/\n\s*\n|\n(?=[A-Z][^\n]{0,80}$)/).filter(block => block.trim());
  let searchOffset = 0;
  blocks.forEach(block => {
    const content = block.trim();
    const textOffset = text.indexOf(content, searchOffset);
    const paragraph = document.createElement('p');
    appendHighlightedText(paragraph, content, textOffset, ranges);
    container.appendChild(paragraph);
    searchOffset = textOffset + content.length;
  });
}

function renderResults(payload, { scroll = true } = {}) {
  const audit = payload.security_audit;
  const score = Math.round(audit.threat_score * 100);
  const threat = audit.is_threat_detected;
  const cleanText = payload.data.clean_text;

  document.querySelector('#verdict').textContent = threat ? 'Potential threat detected' : 'No threat detected';
  document.querySelector('#verdict-icon').textContent = threat ? '!' : '✓';
  document.querySelector('.verdict-card').classList.toggle('threat', threat);
  document.querySelector('#execution-time').textContent = `Completed in ${payload.performance.execution_time_ms.toLocaleString()} ms`;
  document.querySelector('#score').textContent = score;
  const ring = document.querySelector('#score-ring');
  ring.style.setProperty('--score-angle', `${score * 3.6}deg`);
  ring.style.setProperty('--green', score >= 35 ? '#bb3d3d' : score >= 20 ? '#ad6519' : '#147b50');
  document.querySelector('#action-count').textContent = audit.threat_actions_taken.length;
  document.querySelector('#character-count').textContent = cleanText.length.toLocaleString();
  renderFormattedText(cleanText, audit.flagged_elements);
  document.querySelector('#raw-output').textContent = JSON.stringify(payload, null, 2);
  document.querySelector('.raw-output').open = false;

  const actions = document.querySelector('#actions');
  actions.replaceChildren();
  const actionTitle = document.createElement('p');
  actionTitle.className = 'audit-title';
  actionTitle.textContent = 'Actions taken';
  actions.appendChild(actionTitle);
  if (audit.threat_actions_taken.length) {
    audit.threat_actions_taken.forEach(action => addAuditItem(actions, actionLabels[action] || action));
  } else {
    const empty = document.createElement('p');
    empty.className = 'empty-audit';
    empty.textContent = 'No defensive actions were necessary.';
    actions.appendChild(empty);
  }

  const findings = document.querySelector('#findings');
  findings.replaceChildren();
  const findingTitle = document.createElement('p');
  findingTitle.className = 'audit-title';
  findingTitle.textContent = `Findings (${audit.flagged_elements.length})`;
  findings.appendChild(findingTitle);
  if (audit.flagged_elements.length) {
    audit.flagged_elements.forEach(item => addAuditItem(
      findings,
      item.type.replaceAll('_', ' '),
      item.reason,
      item.intercepted_content,
      true,
    ));
  } else {
    const empty = document.createElement('p');
    empty.className = 'empty-audit';
    empty.textContent = 'No suspicious elements or instruction patterns were found.';
    findings.appendChild(empty);
  }

  features.hidden = true;
  results.hidden = false;
  if (scroll) results.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderBatch(payload) {
  const items = Array.isArray(payload?.results) ? payload.results : [];
  const okCount = items.filter(item => item.status === 'success').length;
  const failCount = items.length - okCount;
  document.querySelector('#batch-counts').textContent =
    `${items.length} URL${items.length === 1 ? '' : 's'}: ${okCount} succeeded, ${failCount} failed.` +
    (okCount ? ' Select a successful result to inspect it.' : ' All scans failed.');
  document.querySelector('#batch-raw').textContent = JSON.stringify(payload, null, 2);
  const list = document.querySelector('#batch-list');
  list.replaceChildren();
  detailArea.hidden = true;
  document.querySelector('#batch-detail-note').textContent = '';
  const buttons = [];
  items.forEach((item, index) => {
    const li = document.createElement('li');
    li.className = 'batch-item';
    const urlText = document.createElement('span');
    urlText.className = 'batch-url';
    urlText.textContent = String(item.url ?? '');
    if (item.status === 'success' && item.data && item.security_audit && item.performance) {
      const threat = item.security_audit.is_threat_detected;
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'batch-select';
      button.setAttribute('aria-pressed', 'false');
      const badge = document.createElement('span');
      badge.className = `batch-badge ${threat ? 'threat' : 'ok'}`;
      badge.textContent = threat ? 'Threat detected' : 'No threat detected';
      button.append(`${index + 1}. `, urlText, badge);
      button.addEventListener('click', () => {
        buttons.forEach(other => other.setAttribute('aria-pressed', String(other === button)));
        renderResults(item, { scroll: false });
        detailArea.hidden = false;
        document.querySelector('#batch-detail-note').textContent = `Showing details for result ${index + 1}.`;
        detailArea.scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
      buttons.push(button);
      li.appendChild(button);
    } else {
      li.classList.add('batch-error');
      const row = document.createElement('div');
      row.className = 'batch-row';
      const badge = document.createElement('span');
      badge.className = 'batch-badge error';
      badge.textContent = `Error${item.error?.status_code ? ' ' + item.error.status_code : ''}`;
      row.append(`${index + 1}. `, urlText, badge);
      const detail = document.createElement('p');
      detail.className = 'batch-error-detail';
      detail.textContent = item.error?.detail || 'The page could not be inspected.';
      li.append(row, detail);
    }
    list.appendChild(li);
  });
  batchSummary.hidden = false;
  features.hidden = true;
  results.hidden = false;
  results.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function postJson(url, body) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  let payload;
  try { payload = await response.json(); } catch { payload = null; }
  if (!response.ok) throw new Error(formatDetail(payload?.detail, response.status));
  return payload;
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  resetResults();
  const batch = currentMode() === 'batch';
  const timeout_seconds = Number(document.querySelector('#timeout').value);
  const strict_mode = document.querySelector('#strict-mode').checked;
  setLoading(true);
  try {
    if (batch) {
      const urls = parseBatchUrls();
      const payload = await postJson('/api/v1/sanitize/batch', {
        items: urls.map(url => ({ url, timeout_seconds, strict_mode })),
      });
      if (!Array.isArray(payload?.results)) throw new Error('Unexpected batch response.');
      renderBatch(payload);
    } else {
      const payload = await postJson('/api/v1/sanitize', {
        url: document.querySelector('#url').value,
        timeout_seconds,
        strict_mode,
      });
      batchSummary.hidden = true;
      detailArea.hidden = false;
      renderResults(payload);
    }
  } catch (error) {
    errorBox.textContent = error.message || 'The page could not be inspected.';
    errorBox.hidden = false;
    features.hidden = false;
  } finally {
    setLoading(false);
  }
});

document.querySelector('#new-scan').addEventListener('click', () => {
  resetResults();
  (currentMode() === 'batch' ? document.querySelector('#batch-urls') : document.querySelector('#url')).focus();
  window.scrollTo({ top: 0, behavior: 'smooth' });
});

async function copyFrom(selector, event, resetLabel) {
  await navigator.clipboard.writeText(document.querySelector(selector).textContent);
  const button = event.currentTarget;
  button.textContent = 'Copied';
  setTimeout(() => { button.textContent = resetLabel; }, 1400);
}

document.querySelector('#copy-text').addEventListener('click', event => {
  copyFrom('#formatted-text', event, 'Copy text');
});

document.querySelector('#copy-raw').addEventListener('click', event => {
  copyFrom('#raw-output', event, 'Copy JSON');
});

document.querySelector('#copy-batch').addEventListener('click', event => {
  copyFrom('#batch-raw', event, 'Copy batch JSON');
});
