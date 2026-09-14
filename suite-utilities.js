(() => {
  'use strict';

  const REPOSITORIES = [
    {
      match: '/security-intelligence-library/',
      url: 'https://github.com/peridotan/security-intelligence-library'
    },
    {
      match: '/threat-investigation-dashboard/',
      url: 'https://github.com/peridotan/threat-investigation-dashboard'
    },
    {
      match: '/vulnerability-intelligence-dashboard/',
      url: 'https://github.com/peridotan/vulnerability-intelligence-dashboard'
    }
  ];

  function repositoryUrl() {
    const path = window.location.pathname;
    return REPOSITORIES.find((item) => path.includes(item.match))?.url || null;
  }

  function topbarInner() {
    return document.querySelector('.suite-topbar-inner, .sil-suite-bar__inner');
  }

  function fontControl(inner) {
    return inner?.querySelector('.font-size-control, .sil-font-size-control') || null;
  }

  function ensureUtilities() {
    const inner = topbarInner();
    if (!inner) return;

    let utilities = inner.querySelector('.suite-topbar-utilities');

    if (!utilities) {
      utilities = document.createElement('div');
      utilities.className = 'suite-topbar-utilities';
      inner.appendChild(utilities);
    }

    let repoLink = utilities.querySelector('.suite-repository-link');

    if (!repoLink) {
      const url = repositoryUrl();

      if (url) {
        repoLink = document.createElement('a');
        repoLink.className = 'suite-repository-link';
        repoLink.href = url;
        repoLink.target = '_blank';
        repoLink.rel = 'noopener noreferrer';
        repoLink.textContent = 'GitHub Repository ↗';
        repoLink.setAttribute(
          'aria-label',
          'GitHub Repositoryを新しいタブで開く'
        );
        utilities.appendChild(repoLink);
      }
    }

    const font = fontControl(inner);

    if (font && font.parentElement !== utilities) {
      utilities.appendChild(font);
    }
  }

  function ensureTopButton() {
    const legacyButton = document.getElementById('back-to-top');

    if (legacyButton) {
      legacyButton.classList.add('suite-top-button');
      return;
    }

    let button = document.getElementById('suite-top-button');

    if (!button) {
      button = document.createElement('button');
      button.id = 'suite-top-button';
      button.className = 'suite-top-button';
      button.type = 'button';
      button.textContent = '↑ Top';
      button.setAttribute('aria-label', 'ページ上部へ戻る');

      button.addEventListener('click', () => {
        window.scrollTo({
          top: 0,
          behavior: 'smooth'
        });
      });

      document.body.appendChild(button);
    }

    const syncVisibility = () => {
      button.classList.toggle('is-visible', window.scrollY > 500);
    };

    if (!button.dataset.scrollBound) {
      window.addEventListener('scroll', syncVisibility, {
        passive: true
      });
      button.dataset.scrollBound = 'true';
    }

    syncVisibility();
  }


  function ensureSuiteFooter() {
    if (document.querySelector('.suite-footer')) return;

    const path = window.location.pathname;
    let config = null;

    if (path.includes('/security-intelligence-library/')) {
      config = {
        tool: 'Security Intelligence Library',
        version: '',
        repo: 'https://github.com/peridotan/security-intelligence-library',
        license: 'https://github.com/peridotan/security-intelligence-library/blob/main/LICENSE',
        legal: 'https://github.com/peridotan/security-intelligence-library/blob/main/COPYRIGHT.md',
        legalLabel: 'Copyright / Rights'
      };
    } else if (path.includes('/threat-investigation-dashboard/')) {
      config = {
        tool: 'Threat Investigation',
        version: 'v1.0.3',
        repo: 'https://github.com/peridotan/threat-investigation-dashboard',
        license: './license.html',
        legal: './legal.html',
        legalLabel: 'Legal / Data Notice'
      };
    } else if (path.includes('/vulnerability-intelligence-dashboard/')) {
      config = {
        tool: 'Vulnerability Intelligence',
        version: 'v1.1.0',
        repo: 'https://github.com/peridotan/vulnerability-intelligence-dashboard',
        license: './LICENSE',
        legal: './legal.html',
        legalLabel: 'Legal / Data Sources'
      };
    }

    if (!config) return;

    // Static dashboards already have a compact footer. Replace its presentation
    // with the shared Suite footer while preserving tool-specific attribution above it.
    const directFooter = Array.from(document.body.children).find(
      (node) => node.tagName === 'FOOTER' && !node.classList.contains('md-footer')
    );
    if (directFooter) directFooter.hidden = true;

    // Zensical/Material-style footer metadata duplicates copyright/repository links.
    // Keep any previous/next navigation, but suppress only the metadata strip.
    const themeFooterMeta = document.querySelector('.md-footer-meta');
    if (themeFooterMeta) themeFooterMeta.hidden = true;

    const footer = document.createElement('footer');
    footer.className = 'suite-footer';
    footer.setAttribute('aria-label', 'Security Intelligence Suite footer');

    const versionText = config.version ? ` · ${config.version}` : '';

    footer.innerHTML = `
      <div class="suite-footer-inner">
        <div class="suite-footer-identity">
          <strong>SECURITY INTELLIGENCE SUITE</strong>
          <span>© 2026 peridotan</span>
        </div>
        <div class="suite-footer-tool">
          <strong>${config.tool}</strong>
          <span>${versionText ? versionText.slice(3) : 'Open-source intelligence project'}</span>
        </div>
        <nav class="suite-footer-links" aria-label="Footer links">
          <a href="${config.repo}" target="_blank" rel="noopener noreferrer">GitHub Repository ↗</a>
          <a href="${config.license}" ${config.license.startsWith('http') ? 'target="_blank" rel="noopener noreferrer"' : ''}>License</a>
          <a href="${config.legal}" ${config.legal.startsWith('http') ? 'target="_blank" rel="noopener noreferrer"' : ''}>${config.legalLabel}</a>
        </nav>
      </div>
    `;

    const themeFooter = document.querySelector('.md-footer');
    if (themeFooter) {
      themeFooter.insertAdjacentElement('afterend', footer);
    } else {
      document.body.appendChild(footer);
    }
  }

  function initialize() {
    if (!document.body) return;

    ensureUtilities();
    ensureTopButton();
    ensureSuiteFooter();
  }

  if (typeof document$ !== 'undefined' && document$?.subscribe) {
    document$.subscribe(initialize);
  } else if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize, {
      once: true
    });
  } else {
    initialize();
  }
})();
