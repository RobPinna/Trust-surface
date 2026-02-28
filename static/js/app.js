function levelClass(value) {
  if (value >= 4) return 'text-red-300';
  if (value === 3) return 'text-amber-300';
  return 'text-emerald-300';
}

window.ExposureMapperUI = {
  levelClass,
};

function initTooltips() {
  const tip = document.createElement('div');
  tip.className = 'ui-tooltip hidden';
  tip.setAttribute('role', 'tooltip');
  document.body.appendChild(tip);

  let activeEl = null;

  function hide() {
    tip.classList.add('hidden');
    tip.classList.remove('is-rich');
    activeEl = null;
  }

  function escapeHtml(value) {
    return String(value || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function renderRichTooltip(text) {
    const lines = String(text || '')
      .replace(/\r\n/g, '\n')
      .split('\n')
      .map((line) => String(line || '').trim())
      .filter(Boolean);
    if (!lines.length) {
      tip.textContent = '';
      return;
    }
    const html = lines.map((line) => {
      const safeLine = escapeHtml(line);
      if (/^E-\d{2,3}\s+/i.test(line)) {
        return `<div class="ui-tooltip-line"><span class="wws-signal-text">${safeLine}</span></div>`;
      }
      return `<div class="ui-tooltip-line">${safeLine}</div>`;
    });
    tip.innerHTML = html.join('');
  }

  function show(el) {
    const text = String(el.getAttribute('data-tooltip') || '').trim();
    if (!text) return;
    const rich = String(el.getAttribute('data-tooltip-rich') || '').trim() === '1';
    const near = String(el.getAttribute('data-tooltip-near') || '').trim() === '1';
    activeEl = el;
    tip.classList.toggle('is-rich', rich);
    if (rich) renderRichTooltip(text);
    else tip.textContent = text;
    tip.classList.remove('hidden');

    const rect = el.getBoundingClientRect();
    const pad = 10;
    const maxW = Math.min((rich ? 440 : 360), window.innerWidth - (pad * 2));
    tip.style.maxWidth = `${maxW}px`;
    if (!rich) tip.style.maxHeight = '';
    else tip.style.maxHeight = '300px';

    function clamp(value, min, max) {
      return Math.max(min, Math.min(max, value));
    }

    // Default: above then below. For near tooltips: force non-overlapping placement.
    const tipRect = tip.getBoundingClientRect();
    const gap = near ? 4 : 10;
    const viewportTop = pad;
    const viewportBottom = window.innerHeight - pad;
    const viewportLeft = pad;
    const viewportRight = window.innerWidth - pad;

    const centeredLeft = clamp(
      rect.left + (rect.width / 2) - (tipRect.width / 2),
      viewportLeft,
      Math.max(viewportLeft, viewportRight - tipRect.width)
    );

    let top = rect.top - tipRect.height - gap;
    let left = centeredLeft;

    if (near) {
      const availableAbove = Math.max(0, Math.floor(rect.top - viewportTop - gap));
      const availableBelow = Math.max(0, Math.floor(viewportBottom - rect.bottom - gap));
      let place = 'above';
      if (availableAbove < 96 && availableBelow > availableAbove) place = 'below';
      if (availableBelow < 96 && availableAbove >= availableBelow) place = 'above';

      if (rich) {
        const availableSpace = place === 'above' ? availableAbove : availableBelow;
        const boundedMax = Math.max(96, Math.min(300, availableSpace));
        tip.style.maxHeight = `${boundedMax}px`;
        // Re-measure after max-height change to keep tooltip close to the target.
        const resizedRect = tip.getBoundingClientRect();
        if (place === 'above') top = rect.top - resizedRect.height - gap;
        else top = rect.bottom + gap;
      } else {
        if (place === 'above') top = rect.top - tipRect.height - gap;
        else top = rect.bottom + gap;
      }
      top = clamp(top, viewportTop, Math.max(viewportTop, viewportBottom - tip.getBoundingClientRect().height));
      left = centeredLeft;
    } else {
      if (top < viewportTop) top = rect.bottom + gap;
      top = clamp(top, viewportTop, Math.max(viewportTop, viewportBottom - tipRect.height));
      left = centeredLeft;
    }

    tip.style.top = `${Math.round(top)}px`;
    tip.style.left = `${Math.round(left)}px`;
  }

  document.addEventListener('mouseover', (e) => {
    const el = e.target && e.target.closest ? e.target.closest('[data-tooltip]') : null;
    if (!el) return;
    show(el);
  });
  document.addEventListener('mouseout', (e) => {
    if (!activeEl) return;
    const related = e.relatedTarget;
    if (related && activeEl.contains && activeEl.contains(related)) return;
    hide();
  });
  document.addEventListener('focusin', (e) => {
    const el = e.target && e.target.closest ? e.target.closest('[data-tooltip]') : null;
    if (!el) return;
    show(el);
  });
  document.addEventListener('focusout', () => hide());
  document.addEventListener('scroll', () => hide(), { passive: true });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') hide(); });

  // Tap to toggle (mobile friendly)
  document.addEventListener('click', (e) => {
    const el = e.target && e.target.closest ? e.target.closest('[data-tooltip]') : null;
    if (!el) return;
    if (activeEl === el && !tip.classList.contains('hidden')) {
      hide();
      return;
    }
    show(el);
  });
}

function initOpenDetailsButtons() {
  document.querySelectorAll('[data-open-details]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const id = String(btn.getAttribute('data-open-details') || '').trim();
      if (!id) return;
      const el = document.getElementById(id);
      if (!el || el.tagName.toLowerCase() !== 'details') return;
      el.open = true;
      const body = el.querySelector('.accordion-body');
      if (body) body.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    });
  });
}

function initLoadingOverlay() {
  const overlay = document.getElementById('loadingOverlay');
  const status = document.getElementById('loadingStatus');
  if (!overlay || !status) return;

  const initialMsg = {
    collect: 'Starting collection...',
    model: 'Starting model build...',
    assess: 'Starting risk assessment...',
    report: 'Starting report generation...',
    default: 'Working...',
  };

  let pollTimer = null;
  let activeRequestId = 0;
  let activeRequestStartedAtMs = 0;

  function setMsg(text) {
    status.textContent = text;
    status.classList.remove('animate');
    // Force reflow so the animation reliably restarts.
    // eslint-disable-next-line no-unused-expressions
    status.offsetHeight;
    status.classList.add('animate');
  }

  function resolveAssessmentId(form) {
    const hidden = form.querySelector('input[name="assessment_id"]');
    if (hidden && /^\d+$/.test(String(hidden.value || '').trim())) {
      return Number(hidden.value);
    }
    const action = String(form.getAttribute('action') || '');
    const match = action.match(/\/assessments\/(\d+)/i);
    if (match && match[1]) {
      return Number(match[1]);
    }
    return null;
  }

  function stopPolling() {
    if (pollTimer) window.clearInterval(pollTimer);
    pollTimer = null;
  }

  async function pollProgress(assessmentId, mode, requestId, startedAtMs) {
    if (!assessmentId || requestId !== activeRequestId) return;
    try {
      const url = `/assessments/${assessmentId}/progress?mode=${encodeURIComponent(mode)}`;
      const res = await fetch(url, { cache: 'no-store', headers: { 'X-Requested-With': 'XMLHttpRequest' } });
      if (!res.ok || requestId !== activeRequestId) return;
      const data = await res.json();
      const updatedAt = Date.parse(String((data && data.updated_at) || ''));
      if (Number.isFinite(updatedAt) && Number.isFinite(startedAtMs) && updatedAt < (startedAtMs - 250)) {
        // Ignore stale state left from a previous run of the same mode.
        return;
      }
      const message = String((data && data.message) || '').trim();
      if (message) setMsg(message);
      if (data && data.done) {
        if (!data.success && data.error) {
          setMsg(`Failed: ${String(data.error).slice(0, 120)}`);
        }
        stopPolling();
      }
    } catch (_err) {
      // Keep current message on transient polling failures.
    }
  }

  function show(mode, assessmentId = null) {
    const modeKey = String(mode || 'default').trim() || 'default';
    const firstMsg = initialMsg[modeKey] || initialMsg.default;
    overlay.classList.remove('hidden');
    overlay.setAttribute('aria-hidden', 'false');
    setMsg(firstMsg);

    activeRequestId += 1;
    activeRequestStartedAtMs = Date.now();
    stopPolling();
    if (!assessmentId || !Number.isFinite(assessmentId)) return;

    pollProgress(assessmentId, modeKey, activeRequestId, activeRequestStartedAtMs);
    pollTimer = window.setInterval(() => {
      pollProgress(assessmentId, modeKey, activeRequestId, activeRequestStartedAtMs);
    }, 900);
  }

  function hide() {
    stopPolling();
    overlay.classList.add('hidden');
    overlay.setAttribute('aria-hidden', 'true');
  }

  window.ExposureMapperUI = window.ExposureMapperUI || {};
  window.ExposureMapperUI.showLoading = show;
  window.ExposureMapperUI.hideLoading = hide;

  document.querySelectorAll('form[data-loading]').forEach((form) => {
    form.addEventListener('submit', () => {
      const mode = form.getAttribute('data-loading') || 'default';
      const assessmentId = resolveAssessmentId(form);
      show(mode, assessmentId);
    });
  });
}

function initServerTimeBadge() {
  const el = document.getElementById('serverTimeValue');
  if (!el) return;

  const timeFormat = new Intl.DateTimeFormat(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
  const dateFormat = new Intl.DateTimeFormat(undefined, {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
  });

  const tick = () => {
    const now = new Date();
    el.textContent = `${dateFormat.format(now)} - ${timeFormat.format(now)}`;
  };

  tick();
  window.setInterval(tick, 1000);
}

document.addEventListener('DOMContentLoaded', () => {
  if (window.lucide && typeof window.lucide.createIcons === 'function') {
    window.lucide.createIcons();
  }
  initServerTimeBadge();
  initTooltips();
  initOpenDetailsButtons();
  initLoadingOverlay();
});
