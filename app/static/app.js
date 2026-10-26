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

const urlRows = document.querySelector('#url-rows');
const addUrlButton = document.querySelector('#add-url');
let nextUrlId = 1;
let isLoading = false;

function updateUrlRows() {
  const rows = [...urlRows.querySelectorAll('.url-entry')];
  rows.forEach((row, index) => {
    row.querySelector('label').textContent = `URL ${index + 1}`;
    const removeButton = row.querySelector('.remove-url');
    removeButton.setAttribute('aria-label', `Remove URL ${index + 1}`);
    removeButton.disabled = rows.length === 1;
  });
  addUrlButton.disabled = rows.length >= MAX_BATCH;
  document.querySelector('#url-count').textContent = `${rows.length} / ${MAX_BATCH} URLs`;
  submitButton.querySelector('.button-label').textContent = rows.length > 1 ? `Scan ${rows.length} pages` : 'Scan page';
}

addUrlButton.addEventListener('click', () => {
  if (isLoading || urlRows.children.length >= MAX_BATCH) return;
  const row = urlRows.firstElementChild.cloneNode(true);
  const input = row.querySelector('input');
  input.id = `url-${nextUrlId++}`;
  input.name = input.id;
  input.value = '';
  input.removeAttribute('aria-invalid');
  row.querySelector('label').htmlFor = input.id;
  urlRows.appendChild(row);
  resetResults();
  updateUrlRows();
  input.focus();
});

urlRows.addEventListener('click', event => {
  const button = event.target.closest('.remove-url');
  if (!button || isLoading || urlRows.children.length === 1) return;
  const row = button.closest('.url-entry');
  const focusRow = row.nextElementSibling || row.previousElementSibling;
  row.remove();
  resetResults();
  updateUrlRows();
  focusRow.querySelector('input').focus();
});

function setLoading(loading) {
  isLoading = loading;
  submitButton.disabled = loading;
  document.querySelector('#url-inputs').disabled = loading;
  submitButton.classList.toggle('loading', loading);
  if (loading) {
    submitButton.querySelector('.button-label').textContent = 'Inspecting…';
  } else {
    updateUrlRows();
  }
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

function parseUrls() {
  const inputs = [...urlRows.querySelectorAll('input')];
  inputs.forEach(input => input.removeAttribute('aria-invalid'));
  return inputs.map((input, index) => {
    const value = input.value.trim();
    let parsed;
    try { parsed = new URL(value); } catch { parsed = null; }
    if (!parsed || !['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) {
      input.setAttribute('aria-invalid', 'true');
      input.focus();
      throw new Error(value ? `URL ${index + 1} must be a valid HTTP(S) URL.` : `Enter a URL for row ${index + 1}, or remove that row.`);
    }
    return value;
  });
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
  if (isLoading) return;
  resetResults();
  const timeout_seconds = Number(document.querySelector('#timeout').value);
  const strict_mode = document.querySelector('#strict-mode').checked;
  try {
    const urls = parseUrls();
    setLoading(true);
    if (urls.length > 1) {
      const payload = await postJson('/api/v1/sanitize/batch', {
        items: urls.map(url => ({ url, timeout_seconds, strict_mode })),
      });
      if (!Array.isArray(payload?.results)) throw new Error('Unexpected batch response.');
      renderBatch(payload);
    } else {
      const payload = await postJson('/api/v1/sanitize', {
        url: urls[0],
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
  urlRows.querySelector('input').focus();
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
