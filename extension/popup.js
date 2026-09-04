document.addEventListener('DOMContentLoaded', async () => {
  const targetUrlEl = document.getElementById('targetUrl');
  const loadingEl = document.getElementById('loading');
  const resultsEl = document.getElementById('results');
  const errorEl = document.getElementById('errorBox');
  const riskScoreEl = document.getElementById('riskScore');
  const riskBadgeEl = document.getElementById('riskBadge');
  const phishProbEl = document.getElementById('phishProb');
  const anomalyScoreEl = document.getElementById('anomalyScore');
  const reasonsBoxEl = document.getElementById('reasonsBox');
  const openWebBtn = document.getElementById('openWeb');

  openWebBtn.addEventListener('click', () => {
    chrome.tabs.create({ url: 'http://localhost:8000' });
  });

  try {
    // 1. Query active tab URL
    let activeUrl = 'https://example.com';
    if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.query) {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab && tab.url) {
        activeUrl = tab.url;
      }
    }
    
    targetUrlEl.textContent = activeUrl;

    // Ignore chrome:// or extension pages
    if (activeUrl.startsWith('chrome://') || activeUrl.startsWith('chrome-extension://')) {
      loadingEl.style.display = 'none';
      targetUrlEl.textContent = 'Chrome Internal Page (Skipped)';
      return;
    }

    // 2. Fetch analysis from PHISHGUARD backend API
    const response = await fetch('http://localhost:8000/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: activeUrl })
    });

    if (!response.ok) {
      throw new Error(`API returned HTTP ${response.status}`);
    }

    const data = await response.json();

    // 3. Render analysis results
    loadingEl.style.display = 'none';
    resultsEl.style.display = 'block';

    riskScoreEl.textContent = data.risk_score;
    riskBadgeEl.textContent = `${data.risk_level} RISK`;

    // Apply color badge class
    riskBadgeEl.className = 'badge';
    if (data.risk_level === 'CRITICAL') riskBadgeEl.classList.add('badge-critical');
    else if (data.risk_level === 'HIGH') riskBadgeEl.classList.add('badge-high');
    else if (data.risk_level === 'MEDIUM') riskBadgeEl.classList.add('badge-medium');
    else riskBadgeEl.classList.add('badge-low');

    phishProbEl.textContent = `${(data.phishing_probability * 100).toFixed(1)}%`;
    anomalyScoreEl.textContent = data.anomaly_score.toFixed(2);

    // Reasons
    reasonsBoxEl.innerHTML = '';
    if (data.reasons && data.reasons.length > 0) {
      data.reasons.forEach(reason => {
        const item = document.createElement('div');
        item.className = 'reason-item';
        item.innerHTML = `<div class="reason-dot"></div><div>${reason}</div>`;
        reasonsBoxEl.appendChild(item);
      });
    } else {
      reasonsBoxEl.innerHTML = '<div class="reason-item"><div class="reason-dot"></div><div>No threat signals detected.</div></div>';
    }

  } catch (err) {
    console.error('PhishGuard extension error:', err);
    loadingEl.style.display = 'none';
    errorEl.style.display = 'block';
  }
});
