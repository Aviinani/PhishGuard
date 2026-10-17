'use strict';

(() => {
  const HISTORY_KEY = 'phishguard.scanHistory.v2';
  const MAX_HISTORY = 10;
  const SHORTENERS = new Set([
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
    'buff.ly', 'cutt.ly', 'rb.gy', 'shorturl.at', 'rebrand.ly'
  ]);
  const SUSPICIOUS_WORDS = [
    'login', 'signin', 'verify', 'verification', 'secure', 'account',
    'update', 'password', 'credential', 'wallet', 'banking', 'payment',
    'confirm', 'suspended', 'unlock', 'authenticate', 'recover', 'billing'
  ];
  const KNOWN_BRANDS = [
    'paypal', 'microsoft', 'apple', 'google', 'amazon', 'facebook',
    'instagram', 'netflix', 'whatsapp', 'outlook', 'binance', 'steam'
  ];

  const $ = (id) => document.getElementById(id);
  const form = $('scanForm');
  const urlInput = $('urlInput');
  const clearBtn = $('clearBtn');
  const analyzeBtn = $('analyzeBtn');
  const loading = $('loading');
  const errorMessage = $('errorMessage');
  const errorText = $('errorText');
  const resultsSection = $('resultsSection');
  const resultIcon = $('resultIcon');
  const resultTitle = $('resultTitle');
  const resultDescription = $('resultDescription');
  const riskScore = $('riskScore');
  const riskBar = $('riskBar');
  const riskLevel = $('riskLevel');
  const analyzedUrl = $('analyzedUrl');
  const checksContainer = $('checksContainer');
  const checksCount = $('checksCount');
  const riskFactors = $('riskFactors');
  const riskFactorsCard = $('riskFactorsCard');
  const scanAgainBtn = $('scanAgainBtn');
  const clearHistoryBtn = $('clearHistoryBtn');
  const historyContainer = $('historyContainer');

  let scanHistory = loadHistory();

  function loadHistory() {
    try {
      const parsed = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
      if (!Array.isArray(parsed)) return [];
      return parsed.filter((item) =>
        item && typeof item.url === 'string' &&
        Number.isFinite(Number(item.score)) &&
        typeof item.level === 'string'
      ).slice(0, MAX_HISTORY);
    } catch {
      return [];
    }
  }

  function saveHistory() {
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(scanHistory.slice(0, MAX_HISTORY)));
    } catch {
      // Scanning still works if browser storage is blocked or full.
    }
  }

  function showError(message) {
    errorText.textContent = message;
    errorMessage.classList.remove('hidden');
  }

  function hideError() {
    errorMessage.classList.add('hidden');
  }

  function normalizeAndValidate(rawValue) {
    const value = rawValue.trim();
    if (!value) throw new Error('Enter a URL to begin the scan.');

    // Reject whitespace/control characters rather than guessing what the user intended.
    if (/[\s\u0000-\u001f\u007f]/.test(value)) {
      throw new Error('The URL contains spaces or control characters. Check it and try again.');
    }

    let candidate = value;
    if (!/^[a-zA-Z][a-zA-Z\d+.-]*:/.test(candidate)) {
      candidate = 'https://' + candidate;
    }

    let parsed;
    try {
      parsed = new URL(candidate);
    } catch {
      throw new Error('That URL could not be parsed. Try a format like https://example.com.');
    }

    if (!['http:', 'https:'].includes(parsed.protocol)) {
      throw new Error('Only http:// and https:// website URLs can be analyzed.');
    }
    if (!parsed.hostname || !parsed.hostname.includes('.')) {
      throw new Error('Enter a full domain name, such as https://example.com.');
    }
    if (parsed.username || parsed.password) {
      throw new Error('This URL contains embedded credentials. Remove them before scanning.');
    }

    return parsed;
  }

  function getRegistrableLookingHost(hostname) {
    // A lightweight heuristic only; it is not a Public Suffix List implementation.
    const parts = hostname.toLowerCase().replace(/\.$/, '').split('.');
    if (parts.length <= 2) return hostname.toLowerCase().replace(/\.$/, '');
    const twoPartSuffixes = new Set(['co.uk', 'org.uk', 'com.au', 'net.au', 'co.in', 'com.br', 'co.jp', 'com.sg']);
    const lastTwo = parts.slice(-2).join('.');
    return twoPartSuffixes.has(lastTwo) ? parts.slice(-3).join('.') : lastTwo;
  }

  function analyzeUrl(url) {
    const host = url.hostname.toLowerCase().replace(/\.$/, '');
    const full = url.href.toLowerCase();
    const labels = host.split('.');
    const checks = [];
    const factors = [];
    let score = 0;

    const addCheck = (name, detail, status, points = 0, factor = '') => {
      checks.push({ name, detail, status });
      if (points > 0) {
        score += points;
        factors.push(factor || name);
      }
    };

    const isHttps = url.protocol === 'https:';
    addCheck(
      'Connection scheme',
      isHttps ? 'The URL uses HTTPS. This encrypts the connection but does not prove the site is trustworthy.'
        : 'The URL uses HTTP, so the connection does not provide HTTPS transport encryption.',
      isHttps ? 'safe' : 'warning',
      isHttps ? 0 : 12,
      'The URL uses HTTP instead of HTTPS.'
    );

    const hasIpHost = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || /^\[[0-9a-f:]+\]$/i.test(host);
    addCheck(
      'Hostname format',
      hasIpHost ? 'The address uses an IP literal instead of a typical domain name.' : 'The hostname is expressed as a domain name.',
      hasIpHost ? 'warning' : 'safe',
      hasIpHost ? 18 : 0,
      'The hostname is an IP address rather than a typical domain.'
    );

    const punycode = labels.some((part) => part.startsWith('xn--'));
    addCheck(
      'Internationalized hostname',
      punycode ? 'The hostname contains punycode. This can be legitimate, but similar-looking characters may be used deceptively.'
        : 'No punycode label was detected in the hostname.',
      punycode ? 'warning' : 'safe',
      punycode ? 18 : 0,
      'The hostname contains a punycode label that may need closer inspection.'
    );

    const subdomainCount = Math.max(0, labels.length - 2);
    const manySubdomains = subdomainCount >= 3;
    addCheck(
      'Subdomain structure',
      manySubdomains ? `The hostname contains ${subdomainCount} subdomain labels. Long chains can hide the domain users intended to visit.`
        : `The hostname contains ${subdomainCount} subdomain label(s), which is not unusually complex by this check.`,
      manySubdomains ? 'warning' : 'safe',
      manySubdomains ? Math.min(14, 5 + subdomainCount * 2) : 0,
      'The hostname has an unusually long chain of subdomains.'
    );

    const urlLength = url.href.length;
    const longUrl = urlLength > 120;
    addCheck(
      'URL length',
      longUrl ? `The URL is ${urlLength} characters long. Very long URLs can obscure the destination or add distracting parameters.`
        : `The URL is ${urlLength} characters long, below this check's 120-character warning threshold.`,
      longUrl ? 'warning' : 'safe',
      longUrl ? (urlLength > 200 ? 12 : 7) : 0,
      'The URL is unusually long.'
    );

    const atSymbol = url.href.includes('@');
    addCheck(
      'URL user-info marker',
      atSymbol ? 'An @ character appears in the URL. In some URLs, text before it can mislead readers about the actual host.' : 'No @ character was found in the URL.',
      atSymbol ? 'warning' : 'safe',
      atSymbol ? 18 : 0,
      'The URL contains an @ character that can be used to mislead readers.'
    );

    const shortener = SHORTENERS.has(host);
    addCheck(
      'Link shortener',
      shortener ? 'This hostname belongs to a commonly used link-shortening service, so the final destination is not visible here.'
        : 'The hostname does not match the scanner’s built-in list of common link shorteners.',
      shortener ? 'warning' : 'safe',
      shortener ? 14 : 0,
      'The URL uses a known link-shortening domain.'
    );

    const matchedWords = SUSPICIOUS_WORDS.filter((word) => {
      const pattern = new RegExp(`(^|[^a-z])${word}([^a-z]|$)`, 'i');
      return pattern.test(full);
    });
    const keywordPoints = matchedWords.length ? Math.min(18, 4 + (matchedWords.length - 1) * 3) : 0;
    addCheck(
      'Sensitive-action wording',
      matchedWords.length ? `Found wording often seen in account or credential links: ${matchedWords.slice(0, 5).join(', ')}${matchedWords.length > 5 ? ', …' : ''}. These words can also appear on legitimate sites.`
        : 'No common account-action keywords from the built-in list were detected.',
      matchedWords.length ? 'warning' : 'safe',
      keywordPoints,
      'The URL contains account or credential-related wording.'
    );

    const brandLike = KNOWN_BRANDS.filter((brand) => {
      const hostWithoutWww = host.replace(/^www\./, '');
      return hostWithoutWww.includes(brand) && !getRegistrableLookingHost(hostWithoutWww).split('.')[0].startsWith(brand);
    });
    const suspiciousBrand = brandLike.length > 0;
    addCheck(
      'Brand-name placement',
      suspiciousBrand ? `A known brand name (${brandLike[0]}) appears in a hostname position that may not be the brand’s actual domain. Verify the registered domain independently.`
        : 'No obvious embedded known-brand name was detected by this simple hostname check.',
      suspiciousBrand ? 'warning' : 'safe',
      suspiciousBrand ? 16 : 0,
      'A known brand name may be embedded in a different domain.'
    );

    const hyphenCount = (host.match(/-/g) || []).length;
    const manyHyphens = hyphenCount >= 3;
    addCheck(
      'Hostname punctuation',
      manyHyphens ? `The hostname contains ${hyphenCount} hyphens. This is not proof of phishing, but it can be a useful warning sign.`
        : `The hostname contains ${hyphenCount} hyphen(s).`,
      manyHyphens ? 'warning' : 'safe',
      manyHyphens ? 7 : 0,
      'The hostname contains several hyphens.'
    );

    const port = url.port;
    const unusualPort = Boolean(port && !['80', '443'].includes(port));
    addCheck(
      'Network port',
      unusualPort ? `The URL specifies port ${port}, which is uncommon for an ordinary public website.`
        : 'No unusual explicit port was detected.',
      unusualPort ? 'warning' : 'safe',
      unusualPort ? 10 : 0,
      'The URL specifies a non-standard port.'
    );

    const encodedCount = (url.href.match(/%[0-9a-f]{2}/gi) || []).length;
    const heavyEncoding = encodedCount >= 5;
    addCheck(
      'Encoded characters',
      heavyEncoding ? `The URL contains ${encodedCount} percent-encoded sequences. Encoding is normal in some URLs, but heavy use may make the destination harder to read.`
        : `The URL contains ${encodedCount} percent-encoded sequence(s).`,
      heavyEncoding ? 'warning' : 'safe',
      heavyEncoding ? 7 : 0,
      'The URL contains many encoded characters.'
    );

    const tld = labels[labels.length - 1] || '';
    const unusualTld = tld.length >= 7 || /^\d+$/.test(tld);
    addCheck(
      'Top-level domain shape',
      unusualTld ? `The ending “.${tld}” is unusual by this scanner's simple shape heuristic. A long TLD can still be legitimate.`
        : `The “.${tld}” ending did not trigger this simple shape heuristic.`,
      unusualTld ? 'warning' : 'safe',
      unusualTld ? 5 : 0,
      'The top-level domain has an unusual shape.'
    );

    score = Math.max(0, Math.min(100, score));
    const level = score >= 50 ? 'High Risk' : score >= 25 ? 'Medium Risk' : 'Lower Risk';
    const levelClass = score >= 50 ? 'danger' : score >= 25 ? 'warning' : 'safe';

    return { url: url.href, host, score, level, levelClass, checks, factors };
  }

  function renderResults(result) {
    resultsSection.classList.remove('hidden');
    riskScore.textContent = String(result.score);
    riskBar.style.width = `${result.score}%`;
    riskBar.className = `risk-fill ${result.levelClass}`;
    riskLevel.className = `risk-level ${result.levelClass}`;
    riskLevel.textContent = result.level.toUpperCase();
    analyzedUrl.textContent = result.url;

    resultIcon.className = `result-icon ${result.levelClass}`;
    resultIcon.textContent = result.levelClass === 'danger' ? '!' : result.levelClass === 'warning' ? '△' : '✓';
    resultTitle.textContent = result.levelClass === 'danger' ? 'Several warning signs detected'
      : result.levelClass === 'warning' ? 'Some warning signs detected'
      : 'Fewer warning signs detected';
    resultDescription.textContent = result.levelClass === 'danger'
      ? 'This URL triggered multiple heuristic warnings. Avoid entering sensitive information until you independently verify the destination.'
      : result.levelClass === 'warning'
      ? 'Review the checks below and verify the domain through a trusted source before interacting with the site.'
      : 'The checks found relatively few common warning signs. This does not guarantee that the website is safe.';

    checksContainer.replaceChildren();
    result.checks.forEach((check) => {
      const item = document.createElement('div');
      item.className = 'check-item';
      const icon = document.createElement('span');
      icon.className = `check-icon ${check.status}`;
      icon.setAttribute('aria-hidden', 'true');
      icon.textContent = check.status === 'safe' ? '✓' : check.status === 'warning' ? '!' : '×';
      const copy = document.createElement('div');
      copy.className = 'check-copy';
      const title = document.createElement('strong');
      title.textContent = check.name;
      const detail = document.createElement('p');
      detail.textContent = check.detail;
      copy.append(title, detail);
      item.append(icon, copy);
      checksContainer.append(item);
    });
    checksCount.textContent = `${result.checks.length} checks`;

    riskFactors.replaceChildren();
    if (result.factors.length === 0) {
      const item = document.createElement('li');
      item.className = 'factor-safe';
      item.textContent = 'No major warning patterns were triggered by the current checks. Always verify the destination independently.';
      riskFactors.append(item);
    } else {
      result.factors.forEach((factor) => {
        const item = document.createElement('li');
        item.textContent = factor;
        riskFactors.append(item);
      });
    }
    riskFactorsCard.classList.remove('hidden');
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function addToHistory(result) {
    scanHistory = [{
      url: result.url,
      score: result.score,
      level: result.level,
      levelClass: result.levelClass,
      date: new Date().toISOString()
    }, ...scanHistory.filter((item) => item.url !== result.url)].slice(0, MAX_HISTORY);
    saveHistory();
    renderHistory();
  }

  function renderHistory() {
    historyContainer.replaceChildren();
    if (scanHistory.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'empty-history';
      const symbol = document.createElement('span');
      symbol.setAttribute('aria-hidden', 'true');
      symbol.textContent = '⌁';
      const title = document.createElement('p');
      title.textContent = 'No scans yet';
      const detail = document.createElement('small');
      detail.textContent = 'Your recent URL checks will appear here.';
      empty.append(symbol, title, detail);
      historyContainer.append(empty);
      return;
    }

    scanHistory.forEach((entry) => {
      const row = document.createElement('div');
      row.className = 'history-item';
      const details = document.createElement('div');
      details.style.minWidth = '0';
      const url = document.createElement('div');
      url.className = 'history-url';
      url.title = entry.url;
      url.textContent = entry.url;
      const date = document.createElement('div');
      date.className = 'history-date';
      const parsedDate = new Date(entry.date);
      date.textContent = Number.isNaN(parsedDate.getTime()) ? 'Previous scan' : parsedDate.toLocaleString();
      details.append(url, date);

      const badge = document.createElement('span');
      const levelClass = entry.levelClass || (Number(entry.score) >= 50 ? 'danger' : Number(entry.score) >= 25 ? 'warning' : 'safe');
      badge.className = `history-result ${levelClass}`;
      badge.textContent = entry.level;
      const score = document.createElement('span');
      score.className = 'history-score';
      score.textContent = `${Number(entry.score)}/100`;
      row.append(details, badge, score);
      historyContainer.append(row);
    });
  }

  function setLoading(isLoading) {
    loading.classList.toggle('hidden', !isLoading);
    analyzeBtn.disabled = isLoading;
    analyzeBtn.querySelector('span:nth-child(2)').textContent = isLoading ? 'Analyzing…' : 'Analyze URL';
  }

  function runScan() {
    hideError();
    let parsed;
    try {
      parsed = normalizeAndValidate(urlInput.value);
    } catch (error) {
      showError(error instanceof Error ? error.message : 'Please check the URL and try again.');
      urlInput.focus();
      return;
    }

    setLoading(true);
    // Small delay gives the loading state time to appear; analysis itself is local.
    window.setTimeout(() => {
      try {
        const result = analyzeUrl(parsed);
        renderResults(result);
        addToHistory(result);
      } catch {
        showError('Something went wrong while analyzing this URL. Please try again.');
      } finally {
        setLoading(false);
      }
    }, 180);
  }

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    runScan();
  });

  clearBtn.addEventListener('click', () => {
    urlInput.value = '';
    hideError();
    urlInput.focus();
  });

  scanAgainBtn.addEventListener('click', () => {
    urlInput.value = '';
    hideError();
    urlInput.focus();
    document.querySelector('.scanner-card').scrollIntoView({ behavior: 'smooth', block: 'center' });
  });

  clearHistoryBtn.addEventListener('click', () => {
    scanHistory = [];
    saveHistory();
    renderHistory();
  });

  urlInput.addEventListener('input', hideError);

  renderHistory();
})();
