(() => {
  'use strict';

  const STORAGE_KEY = 'peridotan-threat-investigation-font-size-v1';
  const SIZES = {
    standard: { label: '標準', scale: 1 },
    large: { label: '大', scale: 1.15 },
    xlarge: { label: '特大', scale: 1.30 }
  };
  const root = document.documentElement;
  const managedRules = [];
  let baseRootFontSize = 16;
  let originalRootInlineFontSize = '';

  function isValidSize(value) {
    return Object.prototype.hasOwnProperty.call(SIZES, value);
  }

  function readPreference() {
    try {
      const value = localStorage.getItem(STORAGE_KEY);
      return isValidSize(value) ? value : 'standard';
    } catch (_error) {
      return 'standard';
    }
  }

  function writePreference(value) {
    try {
      localStorage.setItem(STORAGE_KEY, value);
    } catch (_error) {
      // The control still works for the current page if storage is unavailable.
    }
  }

  function compactNumber(value) {
    return Number(value.toFixed(3)).toString();
  }

  function scaleFontSizeValue(value, scale) {
    if (!value || !/\d*\.?\d+px/.test(value)) return value;
    return value.replace(/(-?\d*\.?\d+)px/g, (_match, number) => {
      return `${compactNumber(Number(number) * scale)}px`;
    });
  }

  function collectRules(ruleList) {
    for (const rule of Array.from(ruleList || [])) {
      if (rule.style) {
        const value = rule.style.getPropertyValue('font-size');
        if (value && /\d*\.?\d+px/.test(value)) {
          managedRules.push({
            style: rule.style,
            original: value,
            priority: rule.style.getPropertyPriority('font-size')
          });
        }
      }
      if (rule.cssRules) collectRules(rule.cssRules);
    }
  }

  function collectDashboardFontRules() {
    managedRules.length = 0;
    for (const sheet of Array.from(document.styleSheets)) {
      if (!sheet.href) continue;
      let pathname = '';
      try {
        pathname = new URL(sheet.href, location.href).pathname;
      } catch (_error) {
        continue;
      }
      if (!pathname.endsWith('/style.css') && !pathname.endsWith('/font-size.css')) continue;
      try {
        collectRules(sheet.cssRules);
      } catch (error) {
        console.warn('Font-size control skipped a stylesheet:', error);
      }
    }
    root.dataset.fontSizeManagedRules = String(managedRules.length);
  }

  function applyRuleScale(scale) {
    for (const item of managedRules) {
      item.style.setProperty('font-size', scaleFontSizeValue(item.original, scale), item.priority);
    }
  }

  function applyRootScale(scale) {
    if (scale === 1) {
      if (originalRootInlineFontSize) {
        root.style.fontSize = originalRootInlineFontSize;
      } else {
        root.style.removeProperty('font-size');
      }
      return;
    }
    root.style.fontSize = `${compactNumber(baseRootFontSize * scale)}px`;
  }

  function applyPreference(value, persist = true) {
    const next = isValidSize(value) ? value : 'standard';
    const { label, scale } = SIZES[next];
    root.dataset.fontSize = next;
    applyRootScale(scale);
    applyRuleScale(scale);

    document.querySelectorAll('[data-font-size]').forEach((button) => {
      const active = button.dataset.fontSize === next;
      button.setAttribute('aria-pressed', active ? 'true' : 'false');
    });

    const status = document.getElementById('font-size-status');
    if (status) status.textContent = `文字サイズを${label}に変更しました。`;
    if (persist) writePreference(next);
  }

  function bindControls() {
    document.querySelectorAll('[data-font-size]').forEach((button) => {
      button.addEventListener('click', () => applyPreference(button.dataset.fontSize));
    });
  }

  function init() {
    originalRootInlineFontSize = root.style.fontSize || '';
    baseRootFontSize = parseFloat(getComputedStyle(root).fontSize) || 16;
    collectDashboardFontRules();
    bindControls();
    applyPreference(readPreference(), false);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
  } else {
    init();
  }
})();
