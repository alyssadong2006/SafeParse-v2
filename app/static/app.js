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

function setLoading(loading) {
  submitButton.disabled = loading;
  submitButton.classList.toggle('loading', loading);
  submitButton.querySelector('.button-label').textContent = loading ? 'Inspecting…' : 'Scan page';
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

function renderResults(payload) {
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
  results.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  errorBox.hidden = true;
  results.hidden = true;
  setLoading(true);
  try {
    const response = await fetch('/api/v1/sanitize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: document.querySelector('#url').value,
        timeout_seconds: Number(document.querySelector('#timeout').value),
        strict_mode: document.querySelector('#strict-mode').checked,
      }),
    });
    let payload;
    try { payload = await response.json(); } catch { payload = null; }
    if (!response.ok) throw new Error(payload?.detail || `Request failed with status ${response.status}`);
    renderResults(payload);
  } catch (error) {
    errorBox.textContent = error.message || 'The page could not be inspected.';
    errorBox.hidden = false;
    features.hidden = false;
  } finally {
    setLoading(false);
  }
});

document.querySelector('#new-scan').addEventListener('click', () => {
  results.hidden = true;
  features.hidden = false;
  document.querySelector('#url').focus();
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
