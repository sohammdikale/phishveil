(function () {
  'use strict';

  var SCAN_ENDPOINT = '/api/scan';
  var PROBABILITY_CIRCUMFERENCE = 2 * Math.PI * 60; // r=60 in the SVG ring

  var LOADING_MESSAGES = [
    'Inspecting URL',
    'Analyzing website signals',
    'Running detection',
    'Preparing assessment'
  ];

  var form = document.getElementById('scanForm');
  var input = document.getElementById('urlInput');
  var button = document.getElementById('scanButton');
  var errorBox = document.getElementById('errorBox');
  var loadingBox = document.getElementById('loadingBox');
  var loadingText = document.getElementById('loadingText');
  var resultSection = document.getElementById('resultSection');
  var resetButton = document.getElementById('resetButton');

  var loadingInterval = null;
  var loadingIndex = 0;

  if (form) {
    form.addEventListener('submit', function (event) {
      event.preventDefault();
      scanWebsite();
    });
  }

  if (resetButton) {
    resetButton.addEventListener('click', resetResults);
  }

  function scanWebsite() {
    var url = (input.value || '').trim();

    hideError();

    if (!url) {
      showError('Enter a website URL to scan.');
      input.focus();
      return;
    }

    resultSection.hidden = true;
    showLoading();
    button.disabled = true;

    fetch(SCAN_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url })
    })
      .then(function (response) {
        return response.json().then(function (data) {
          return { status: response.status, data: data };
        });
      })
      .then(function (result) {
        hideLoading();
        button.disabled = false;

        if (!result.data || result.data.ok !== true) {
          var message = (result.data && result.data.error) || 'The URL could not be analysed. Check it and try again.';
          showError(message);
          return;
        }

        displayResult(result.data);
      })
      .catch(function () {
        hideLoading();
        button.disabled = false;
        showError('Phishveil could not reach the scanner. Check your connection and try again.');
      });
  }

  function showLoading() {
    loadingIndex = 0;
    loadingText.textContent = LOADING_MESSAGES[0] + '…';
    loadingBox.hidden = false;

    loadingInterval = window.setInterval(function () {
      loadingIndex = (loadingIndex + 1) % LOADING_MESSAGES.length;
      loadingText.textContent = LOADING_MESSAGES[loadingIndex] + '…';
    }, 1400);
  }

  function hideLoading() {
    loadingBox.hidden = true;
    if (loadingInterval) {
      window.clearInterval(loadingInterval);
      loadingInterval = null;
    }
  }

  function showError(message) {
    errorBox.textContent = message;
    errorBox.hidden = false;
  }

  function hideError() {
    errorBox.hidden = true;
    errorBox.textContent = '';
  }

  function displayResult(data) {
    resultSection.hidden = false;
    resultSection.dataset.risk = data.risk || 'suspicious';

    var statusLabel = document.getElementById('statusLabel');
    statusLabel.textContent = (data.risk || '').toUpperCase();

    var headline = document.getElementById('resultHeadline');
    headline.textContent = headlineFor(data.risk, data.prediction);

    animateProbability(data.phishing_probability);
    animateConfidence(data.confidence);

    var analyzedUrlValue = document.getElementById('analyzedUrlValue');
    var normalizedUrl = (data.details && data.details.normalized_url) || '';
    analyzedUrlValue.textContent = normalizedUrl;

    displayDetails(data);
    displayReasons(data);

    var disclaimerBox = document.getElementById('disclaimerBox');
    var disclaimerText = document.getElementById('disclaimerText');
    if (data.disclaimer) {
      disclaimerText.textContent = data.disclaimer;
      disclaimerBox.hidden = false;
    } else {
      disclaimerBox.hidden = true;
    }

    resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function headlineFor(risk, prediction) {
    if (risk === 'safe') return 'Likely legitimate';
    if (risk === 'dangerous') return 'Likely phishing';
    if (risk === 'suspicious') return 'Suspicious website';
    return prediction || 'Assessment complete';
  }

  function animateProbability(value) {
    var numeric = typeof value === 'number' ? value : 0;
    var arc = document.getElementById('probabilityArc');
    var valueLabel = document.getElementById('probabilityValue');

    var offset = PROBABILITY_CIRCUMFERENCE - (numeric / 100) * PROBABILITY_CIRCUMFERENCE;
    // Force layout so the transition from the reset state plays.
    arc.style.strokeDashoffset = PROBABILITY_CIRCUMFERENCE;
    window.requestAnimationFrame(function () {
      window.requestAnimationFrame(function () {
        arc.style.strokeDashoffset = offset;
      });
    });

    animateNumber(valueLabel, numeric, function (n) {
      return Math.round(n) + '%';
    });
  }

  function animateConfidence(value) {
    var numeric = typeof value === 'number' ? value : 0;
    var fill = document.getElementById('confidenceFill');
    var valueLabel = document.getElementById('confidenceValue');

    fill.style.width = '0%';
    window.requestAnimationFrame(function () {
      window.requestAnimationFrame(function () {
        fill.style.width = numeric + '%';
      });
    });

    animateNumber(valueLabel, numeric, function (n) {
      return n.toFixed(1) + '%';
    });
  }

  function animateNumber(el, target, formatter) {
    var start = 0;
    var duration = 700;
    var startTime = null;

    function step(timestamp) {
      if (startTime === null) startTime = timestamp;
      var progress = Math.min((timestamp - startTime) / duration, 1);
      var current = start + (target - start) * progress;
      el.textContent = formatter(current);
      if (progress < 1) {
        window.requestAnimationFrame(step);
      } else {
        el.textContent = formatter(target);
      }
    }

    window.requestAnimationFrame(step);
  }

  function displayDetails(data) {
    var grid = document.getElementById('detailsGrid');
    var warningsList = document.getElementById('warningsList');
    grid.innerHTML = '';
    warningsList.innerHTML = '';

    var details = data.details || {};
    var page = details.page || {};

    var rows = [
      ['Hostname', details.hostname],
      ['Registered domain', details.registered_domain],
      ['HTTPS', typeof details.uses_https === 'boolean' ? (details.uses_https ? 'Yes' : 'No') : undefined],
      ['URL length', details.url_length],
      ['Dots', details.dots],
      ['Hyphens', details.hyphens],
      ['Subdomains', details.subdomains],
      ['IP address host', typeof details.ip_address === 'boolean' ? (details.ip_address ? 'Yes' : 'No') : undefined],
      ['Phishing terms', details.phishing_terms],
      ['Page fetched', typeof page.fetched === 'boolean' ? (page.fetched ? 'Yes' : 'No') : undefined],
      ['Page status', page.status_code],
      ['Page title', page.title],
      ['Final URL', page.final_url]
    ];

    rows.forEach(function (pair) {
      var label = pair[0];
      var value = pair[1];
      if (value === undefined || value === null || value === '') return;

      var wrapper = document.createElement('div');
      var dt = document.createElement('dt');
      var dd = document.createElement('dd');
      dt.textContent = label;
      dd.textContent = String(value);
      wrapper.appendChild(dt);
      wrapper.appendChild(dd);
      grid.appendChild(wrapper);
    });

    (details.warnings || []).forEach(function (warning) {
      var li = document.createElement('li');
      li.textContent = warning;
      warningsList.appendChild(li);
    });
  }

  function displayReasons(data) {
    var list = document.getElementById('reasonsList');
    list.innerHTML = '';

    (data.reasons || []).forEach(function (reason) {
      var li = document.createElement('li');
      li.dataset.type = reason.type || 'neutral';

      var icon = document.createElement('span');
      icon.className = 'reason-icon';
      icon.setAttribute('aria-hidden', 'true');
      icon.textContent = reason.type === 'positive' ? '✓' : reason.type === 'negative' ? '⚠' : '•';

      var text = document.createElement('span');
      text.textContent = reason.text;

      li.appendChild(icon);
      li.appendChild(text);
      list.appendChild(li);
    });
  }

  function resetResults() {
    resultSection.hidden = true;
    hideError();
    input.value = '';
    input.focus();
    window.scrollTo({ top: document.getElementById('scanner').offsetTop - 90, behavior: 'smooth' });
  }

  // Mobile nav toggle
  var nav = document.querySelector('.nav');
  var navToggle = document.getElementById('navToggle');
  if (navToggle && nav) {
    navToggle.addEventListener('click', function () {
      var isOpen = nav.classList.toggle('is-open');
      navToggle.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
    });
  }
})();