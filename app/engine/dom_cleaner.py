"""Browser-side DOM visibility inspection script."""

"""
Injects JavaScript code into a webpage. 
Inspects webpage for:
1. Hidden attributes: Elements marked with `hidden` or `aria-hidden="true"`.
2. CSS properties: Elements with `display: none`, `visibility: hidden`, `opacity: 0`, 
   `font-size: 0`, or clipped content.
3. Zero font size or clipped content: Text formatted with `font-size: 0` or clipped 
   using `clip-path` or `clip`.
4. Color matching: Text with foreground color matching the background color.
5. Off-screen positioning: Elements positioned off-screen using `position: absolute` or
   `position: fixed` with coordinates outside the viewport.
"""
DOM_CLEANER_SCRIPT = r"""
() => {
  const findings = [];
  const marked = 'data-safeparse-remove';

  function parseColor(value) {
    const match = value && value.match(/rgba?\(([^)]+)\)/i);
    if (!match) return null;
    const parts = match[1].split(/[ ,/]+/).filter(Boolean).map(Number);
    return parts.length >= 3 ? [parts[0], parts[1], parts[2], parts.length > 3 ? parts[3] : 1] : null;
  }

  function sameColor(fg, bg) {
    if (!fg || !bg || fg[3] <= 0.05 || bg[3] <= 0.05) return false;
    return Math.abs(fg[0] - bg[0]) + Math.abs(fg[1] - bg[1]) + Math.abs(fg[2] - bg[2]) < 12;
  }

  function effectiveBackground(el) {
    for (let node = el; node; node = node.parentElement) {
      const color = parseColor(getComputedStyle(node).backgroundColor);
      if (color && color[3] > 0.05) return color;
    }
    return [255, 255, 255, 1]; // Browser canvas default.
  }

  function reasonFor(el) {
    const style = getComputedStyle(el);
    if (el.hidden) return 'hidden attribute';
    if (el.getAttribute('aria-hidden') === 'true') return 'aria-hidden: true';
    if (style.display === 'none') return 'display: none';
    if (style.visibility === 'hidden' || style.visibility === 'collapse') return 'visibility: ' + style.visibility;
    if (Number(style.opacity) <= 0.01) return 'opacity: 0';
    if (parseFloat(style.fontSize) <= 0.5) return 'font-size: 0';
    if (style.clipPath === 'inset(100%)' || style.clip === 'rect(0px, 0px, 0px, 0px)') return 'content clipped';

    const text = (el.innerText || el.textContent || '').trim();
    if (text && sameColor(parseColor(style.color), effectiveBackground(el))) {
      return 'foreground color matches background color';
    }

    const rect = el.getBoundingClientRect();
    const positioned = style.position === 'absolute' || style.position === 'fixed';
    if (positioned && (rect.right < -100 || rect.bottom < -100 || rect.left > document.documentElement.scrollWidth + 100)) {
      return 'positioned off-screen';
    }
    return null;
  }

  const elements = Array.from(document.body ? document.body.querySelectorAll('*') : []);
  if (document.body) elements.unshift(document.body);
  for (const el of elements) {
    if (el.closest('script,style,noscript,template,svg,canvas,iframe')) continue;
    if (el.parentElement && el.parentElement.closest('[' + marked + ']')) continue;
    const reason = reasonFor(el);
    if (reason) {
      el.setAttribute(marked, 'true');
      const content = (el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 500);
      if (content) findings.push({type: 'hidden_css', reason, intercepted_content: content});
    }
  }

  if (!document.body || document.body.hasAttribute(marked)) return {text: '', findings};
  const clone = document.body.cloneNode(true);
  clone.querySelectorAll('script,style,noscript,template,svg,canvas,iframe,[' + marked + ']').forEach(node => node.remove());
  const text = (clone.innerText || clone.textContent || '')
    .replace(/[ \t]+/g, ' ')
    .replace(/\n\s*\n\s*\n+/g, '\n\n')
    .trim();
  return {text, findings};
}
"""
