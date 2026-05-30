// CRX-Shield Dashboard Controller

let extensionsData = []; // Cache for extension scan results
let whitelistedIds = new Set(); // Set of whitelisted extension IDs
let hostOnline = false;

// DOM Elements
const extensionsList = document.getElementById('extensions-list');
const emptyState = document.getElementById('empty-state');
const loadingSpinner = document.getElementById('loading-spinner');
const runAuditBtn = document.getElementById('run-audit-btn');
const searchInput = document.getElementById('search-input');
const sortSelect = document.getElementById('sort-select');
const hostStatusCircle = document.getElementById('host-status-circle');
const hostStatusText = document.getElementById('host-status-text');
const consoleLogs = document.getElementById('console-logs');

// Stat Cards
const statTotal = document.getElementById('stat-total');
const statThreats = document.getElementById('stat-threats');
const statWhitelisted = document.getElementById('stat-whitelisted');

// Alert Banner Elements
const alertBanner = document.getElementById('alert-banner');
const alertExtName = document.getElementById('alert-ext-name');
const alertExtScore = document.getElementById('alert-ext-score');
const alertDisableBtn = document.getElementById('alert-disable-btn');
const alertDismissBtn = document.getElementById('alert-dismiss-btn');

// --- Helper Functions ---

function addLog(text, type = 'system') {
  const line = document.createElement('div');
  line.className = `log-line log-${type}`;
  const timestamp = new Date().toLocaleTimeString();
  line.textContent = `[${timestamp}] ${text}`;
  consoleLogs.appendChild(line);
  consoleLogs.scrollTop = consoleLogs.scrollHeight;
}

// Check if Python Native Messaging Host is registered and working
function checkHostConnection() {
  return new Promise((resolve) => {
    addLog('[System] Testing connection to Python Host Engine...');
    
    // We send a ping-like message using a mock/dummy ID.
    // The Python host will respond with status: 'not_found' or similar, proving it is running.
    chrome.runtime.sendMessage({ action: 'scan_extension', id: 'ping' }, (response) => {
      if (response && response.status !== 'error') {
        hostOnline = true;
        hostStatusCircle.className = 'status-circle status-online';
        hostStatusText.textContent = 'Scanner Online (Python)';
        addLog('[System] Python Host Connection: ONLINE', 'python');
        resolve(true);
      } else {
        hostOnline = false;
        hostStatusCircle.className = 'status-circle status-offline';
        const errMsg = (response && response.error) ? response.error : 'Connection failed';
        hostStatusText.textContent = 'Scanner Offline';
        addLog(`[Error] Python Host Connection: OFFLINE (${errMsg})`, 'error');
        addLog('[System] Please run register.py to configure registry policies.', 'system');
        resolve(false);
      }
    });
  });
}

// Load whitelisted IDs from chrome.storage
function loadWhitelist() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['whitelistedIds'], (result) => {
      if (result.whitelistedIds) {
        whitelistedIds = new Set(result.whitelistedIds);
      }
      addLog(`[System] Whitelist loaded (${whitelistedIds.size} approved extensions).`);
      resolve();
    });
  });
}

// Toggle whitelist status for an extension
function toggleWhitelist(extId, name) {
  if (whitelistedIds.has(extId)) {
    whitelistedIds.delete(extId);
    addLog(`[System] Removed "${name}" from whitelist.`, 'system');
  } else {
    whitelistedIds.add(extId);
    addLog(`[System] Whitelisted "${name}" (Green Flagged).`, 'python');
  }
  
  chrome.storage.local.set({ whitelistedIds: Array.from(whitelistedIds) }, () => {
    updateOverviewStats();
    renderExtensionsList();
  });
}

// Evaluate dynamic reputation based on static database and live CWS metrics
function evaluateReputation(ext) {
  // 1. Check local static whitelist database first
  const staticMatch = typeof TRUSTED_EXTENSIONS !== 'undefined' && TRUSTED_EXTENSIONS[ext.id];
  if (staticMatch) {
    return {
      verified: true,
      name: staticMatch.name,
      category: staticMatch.category,
      desc: staticMatch.description,
      source: 'static'
    };
  }

  // 2. Check dynamic scraped CWS reputation
  if (ext.reputation && ext.reputation.status === 'success') {
    const rep = ext.reputation;
    
    // Evaluation Policy:
    // - Popularity: >= 50,000 users
    // - Rating: >= 4.0 average
    // - Engagement: >= 100 reviews
    const meetThreshold = rep.users >= 50000 && rep.rating >= 4.0 && rep.reviews >= 100;
    
    // Safety check: Ensure no Critical or High threat code findings are present (obfuscation, spyware, etc.)
    // We allow High/Critical permission capabilities, but reject High/Critical code behaviors.
    const hasHighCodeThreats = ext.findings && ext.findings.some(f => 
      (f.severity === 'HIGH' || f.severity === 'CRITICAL') && f.category !== 'Permission'
    );
    
    if (meetThreshold && !hasHighCodeThreats) {
      // Format user downloads display count (e.g. 1.7M or 50K)
      let formattedUsers = rep.users;
      if (rep.users >= 1000000) {
        formattedUsers = (rep.users / 1000000).toFixed(1).replace('.0', '') + 'M';
      } else if (rep.users >= 1000) {
        formattedUsers = (rep.users / 1000).toFixed(0) + 'K';
      }
      
      return {
        verified: true,
        name: rep.name,
        category: 'Chrome Web Store',
        desc: `${formattedUsers}+ users, ${rep.rating.toFixed(1)}★ (${rep.reviews} reviews)`,
        source: 'dynamic',
        users: formattedUsers,
        rating: rep.rating,
        reviews: rep.reviews
      };
    }
  }

  return { verified: false };
}

// Update the overall system health panel based on scanned extensions
function updateOverviewStats() {
  const total = extensionsData.length;
  let threats = 0;
  let whitelisted = 0;

  extensionsData.forEach(ext => {
    const repInfo = evaluateReputation(ext);
    if (whitelistedIds.has(ext.id) || repInfo.verified) {
      whitelisted++;
    } else if (ext.risk_score >= 70) {
      threats++;
    }
  });

  statTotal.textContent = total;
  statThreats.textContent = threats;
  statWhitelisted.textContent = whitelisted;

  // Update central health status card
  const healthCard = document.getElementById('health-status-card');
  const indicator = document.getElementById('health-indicator');
  const title = document.getElementById('health-status-title');
  const desc = document.getElementById('health-status-desc');

  if (!hostOnline) {
    indicator.className = 'health-indicator pulse-warning';
    title.textContent = 'Scanner Disconnected';
    desc.textContent = 'Python host engine is offline. Full file scans cannot be performed.';
  } else if (threats > 0) {
    indicator.className = 'health-indicator pulse-danger';
    title.textContent = 'Security Threats Found';
    desc.textContent = `${threats} extensions are classified as HIGH risk. Review details below.`;
  } else {
    indicator.className = 'health-indicator pulse-green';
    title.textContent = 'System Protected';
    desc.textContent = 'All extensions scanned. No high-threat scripts or manifests detected.';
  }
}

// Render the cached extensions to the UI after applying filtering and sorting
function renderExtensionsList() {
  const query = searchInput.value.toLowerCase().strip ? searchInput.value.toLowerCase().trim() : searchInput.value.toLowerCase();
  const sortBy = sortSelect.value;

  // Filter list
  let filtered = extensionsData.filter(ext => {
    const matchesName = ext.name.toLowerCase().includes(query);
    const matchesId = ext.id.toLowerCase().includes(query);
    const matchesDesc = (ext.description && ext.description.toLowerCase().includes(query));
    
    // Check if query matches any permission
    const matchesPermission = ext.permissions && ext.permissions.some(p => p.toLowerCase().includes(query));
    
    return matchesName || matchesId || matchesDesc || matchesPermission;
  });

  // Sort list
  filtered.sort((a, b) => {
    if (sortBy === 'risk-desc') {
      return b.risk_score - a.risk_score;
    } else if (sortBy === 'risk-asc') {
      return a.risk_score - b.risk_score;
    } else if (sortBy === 'name-asc') {
      return a.name.localeCompare(b.name);
    }
    return 0;
  });

  // Clear list
  extensionsList.innerHTML = '';
  
  if (filtered.length === 0) {
    emptyState.classList.remove('hide');
    return;
  }
  emptyState.classList.add('hide');

  filtered.forEach(ext => {
    const card = document.createElement('div');
    card.className = 'extension-card';
    card.id = `card-${ext.id}`;

    const repInfo = evaluateReputation(ext);

    // Risk badge color selection
    let scoreClass = 'risk-safe';
    let riskLabel = 'Low Risk';
    if (whitelistedIds.has(ext.id) || repInfo.verified) {
      scoreClass = 'risk-safe';
      riskLabel = repInfo.verified ? 'Verified Safe' : 'Whitelisted';
    } else if (ext.risk_score >= 75) {
      scoreClass = 'risk-critical';
      riskLabel = 'Critical Threat';
    } else if (ext.risk_score >= 50) {
      scoreClass = 'risk-danger';
      riskLabel = 'High Risk';
    } else if (ext.risk_score >= 30) {
      scoreClass = 'risk-warning';
      riskLabel = 'Medium Risk';
    }

    // Status Badge
    let statusBadge = `<span class="badge badge-enabled">Enabled</span>`;
    if (!ext.enabled) {
      statusBadge = `<span class="badge badge-disabled">Disabled</span>`;
    }
    if (repInfo.verified) {
      statusBadge += ` <span class="badge badge-verified">Verified Safe</span>`;
    } else if (whitelistedIds.has(ext.id)) {
      statusBadge += ` <span class="badge badge-whitelisted">Whitelisted</span>`;
    }

    const firstLetter = ext.name.charAt(0).toUpperCase();

    // Compile dynamic Web Store reputation statistics block
    let reputationHTML = '';
    if (ext.reputation && ext.reputation.status === 'success') {
      const rep = ext.reputation;
      let formattedUsers = rep.users;
      if (rep.users >= 1000000) {
        formattedUsers = (rep.users / 1000000).toFixed(1).replace('.0', '') + 'M+';
      } else if (rep.users >= 1000) {
        formattedUsers = (rep.users / 1000).toFixed(0) + 'K+';
      }
      
      let formattedReviews = rep.reviews;
      if (rep.reviews >= 1000) {
        formattedReviews = (rep.reviews / 1000).toFixed(1).replace('.0', '') + 'K';
      }
      
      reputationHTML = `
        <div class="ext-reputation-line" style="font-size: 0.78rem; color: var(--text-secondary); margin-top: 6px; display: flex; align-items: center; gap: 8px;">
          <span>🌐 Store Reputation:</span>
          <a href="https://chromewebstore.google.com/detail/${ext.id}/reviews" target="_blank" class="cws-reviews-link" style="color: var(--accent-color); text-decoration: underline; font-weight: 600; display: inline-flex; align-items: center; gap: 3px;" title="Click to view reviews on Chrome Web Store">
            ⭐ ${rep.rating.toFixed(1)} (${formattedReviews} reviews)
          </a>
          <span>•</span>
          <span>👥 ${formattedUsers} users</span>
        </div>
      `;
    }

    // Compile findings
    let findingsHTML = '';
    let verifiedRow = '';
    
    if (repInfo.verified) {
      const sourceLabel = repInfo.source === 'dynamic' ? 'OSINT Reputation' : 'Signature Whitelist';
      verifiedRow = `
        <div class="finding-row" style="border: 1px solid rgba(59, 130, 246, 0.3); background: rgba(59, 130, 246, 0.05); margin-bottom: 8px; width: 100%;">
          <span class="finding-severity sev-info">[VERIFIED]</span>
          <span class="finding-desc">Matches popular trusted extension [${repInfo.name}] via ${sourceLabel}: <strong>${repInfo.desc}</strong>.</span>
        </div>
      `;
    }

    if (ext.findings && ext.findings.length > 0) {
      findingsHTML = `
        <div class="ext-card-findings">
          <div class="findings-header">Static Audit Findings (${ext.findings.length + (repInfo.verified ? 1 : 0)})</div>
          ${verifiedRow}
          ${ext.findings.map(f => {
            const sevClass = `sev-${(f.severity || 'info').toLowerCase()}`;
            return `
              <div class="finding-row">
                <span class="finding-severity ${sevClass}">[${f.severity || 'INFO'}]</span>
                <span class="finding-desc">${f.desc}</span>
              </div>
            `;
          }).join('')}
        </div>
      `;
    } else if (repInfo.verified) {
      findingsHTML = `
        <div class="ext-card-findings">
          <div class="findings-header">Static Audit Findings (1)</div>
          ${verifiedRow}
        </div>
      `;
    } else if (hostOnline) {
      findingsHTML = `
        <div class="ext-card-findings">
          <div class="findings-header">Static Audit Findings (0)</div>
          <div class="finding-row">
            <span class="finding-severity sev-low">[SAFE]</span>
            <span class="finding-desc">No suspicious API calls, permissions, or code patterns detected.</span>
          </div>
        </div>
      `;
    }

    const displayedScore = (whitelistedIds.has(ext.id) || repInfo.verified) ? 0 : ext.risk_score;

    card.innerHTML = `
      <div class="ext-card-header">
        <div class="ext-info-block" style="cursor: pointer;" title="Click to toggle details">
          <div class="ext-icon-fallback">${firstLetter}</div>
          <div class="ext-details">
            <h3 style="display: flex; align-items: center; gap: 8px;">
              ${ext.name}
              <span class="chevron-icon" style="font-size: 0.8rem; color: var(--text-secondary); transition: transform 0.3s cubic-bezier(0.16, 1, 0.3, 1);">▼</span>
            </h3>
            <div class="ext-meta-sub">
              <span>v${ext.version}</span>
              <span>•</span>
              <span class="ext-id-font">${ext.id}</span>
              <span>•</span>
              ${statusBadge}
            </div>
            ${reputationHTML}
          </div>
        </div>

        <div class="ext-risk-gauge-container">
          <div class="risk-circle ${scoreClass}" title="Threat Risk Score: ${displayedScore}/100">
            ${displayedScore}
          </div>
        </div>
      </div>

      ${findingsHTML}

      <div class="ext-card-actions">
        <button class="btn btn-secondary btn-card details-btn">View Details</button>
        <button class="btn btn-secondary btn-card whitelist-btn">${whitelistedIds.has(ext.id) ? 'Revoke Trust' : 'Green Flag'}</button>
        <button class="btn btn-secondary btn-card toggle-btn">${ext.enabled ? 'Disable' : 'Enable'}</button>
        <button class="btn btn-danger-filled btn-card uninstall-btn">Uninstall</button>
      </div>
    `;

    // Toggle details panel accordion function
    const findingsPanel = card.querySelector('.ext-card-findings');
    const detailsBtn = card.querySelector('.details-btn');
    const chevron = card.querySelector('.chevron-icon');
    const headerBlock = card.querySelector('.ext-info-block');

    function toggleDetails(e) {
      // Prevent details accordion toggle if user clicked on the reviews anchor link
      if (e && e.target && e.target.closest('.cws-reviews-link')) {
        return;
      }
      if (findingsPanel) {
        const isExpanded = findingsPanel.classList.toggle('expanded');
        detailsBtn.textContent = isExpanded ? 'Hide Details' : 'View Details';
        if (chevron) {
          chevron.style.transform = isExpanded ? 'rotate(180deg)' : '';
          chevron.style.color = isExpanded ? 'var(--accent-color)' : '';
        }
      }
    }

    if (detailsBtn) detailsBtn.addEventListener('click', toggleDetails);
    if (headerBlock) headerBlock.addEventListener('click', toggleDetails);

    // Hook buttons
    card.querySelector('.whitelist-btn').addEventListener('click', () => {
      toggleWhitelist(ext.id, ext.name);
    });

    card.querySelector('.toggle-btn').addEventListener('click', () => {
      const nextState = !ext.enabled;
      chrome.management.setEnabled(ext.id, nextState, () => {
        addLog(`[System] Extension "${ext.name}" has been ${nextState ? 'enabled' : 'disabled'}.`);
        ext.enabled = nextState;
        renderExtensionsList();
        updateOverviewStats();
      });
    });

    card.querySelector('.uninstall-btn').addEventListener('click', () => {
      addLog(`[System] Prompting uninstall for "${ext.name}"...`);
      chrome.management.uninstall(ext.id, { showConfirmDialog: true }, () => {
        // Will refresh the list automatically via management listeners
      });
    });

    extensionsList.appendChild(card);
  });
}

// Main logic to fetch all extensions and analyze them with the Python host
async function performScan() {
  loadingSpinner.classList.remove('hide');
  extensionsList.classList.add('hide');
  emptyState.classList.add('hide');
  addLog('[System] Initiating full system extension scan...');

  chrome.runtime.sendMessage({ action: 'get_all_extensions' }, async (extensions) => {
    if (!extensions || extensions.length === 0) {
      extensionsData = [];
      loadingSpinner.classList.add('hide');
      emptyState.classList.remove('hide');
      updateOverviewStats();
      addLog('[System] No extensions found.');
      return;
    }

    extensionsData = [];
    addLog(`[Scanner] Found ${extensions.length} extensions. Loading files...`);

    for (let ext of extensions) {
      addLog(`[Scanner] Audit started for "${ext.name}" (${ext.id})...`);
      
      // Request native file scan from Python backend via background worker
      const scanPromise = new Promise((resolve) => {
        chrome.runtime.sendMessage({ action: 'scan_extension', id: ext.id }, (response) => {
          resolve(response);
        });
      });

      const response = await scanPromise;
      let riskScore = 0;
      let findings = [];

      if (response && response.status === 'success') {
        riskScore = response.risk_score;
        findings = response.findings;
        addLog(`[Python] Analysed "${ext.name}". Score: ${riskScore}/100. Warnings: ${findings.length}`, 'python');
      } else if (response && response.status === 'not_found') {
        riskScore = 5; // Default low risk baseline
        findings = response.findings || [];
        addLog(`[Scanner] Unpacked files not found for "${ext.name}". Using baseline metadata.`, 'warning');
      } else {
        riskScore = 10;
        findings = [{ severity: 'LOW', category: 'Scanner', desc: response ? response.error : 'Python host communication failed.' }];
        addLog(`[Error] Failed to read files for "${ext.name}".`, 'error');
      }

      extensionsData.push({
        id: ext.id,
        name: ext.name,
        version: ext.version,
        description: ext.description,
        enabled: ext.enabled,
        risk_score: riskScore,
        findings: findings,
        permissions: ext.permissions || [],
        reputation: response ? response.reputation : null
      });
    }

    loadingSpinner.classList.add('hide');
    extensionsList.classList.remove('hide');
    updateOverviewStats();
    renderExtensionsList();
    addLog('[System] Full audit completed successfully.', 'python');
  });
}

// Check URL query string for threat highlights (real-time alert redirection)
function checkAlertQueries() {
  const params = new URLSearchParams(window.location.search);
  const highlightId = params.get('highlight');
  const risk = params.get('risk');
  const name = params.get('name');

  if (highlightId && risk && name) {
    alertExtName.textContent = name;
    alertExtScore.textContent = risk;
    alertBanner.classList.remove('hide');
    addLog(`[ALERT] Real-time warning triggered for high risk extension: ${name} (${highlightId})`, 'error');
    
    // Clear URL parameters to prevent re-triggering alert on page reload
    window.history.replaceState({}, document.title, window.location.pathname);

    // Alert Actions
    alertDisableBtn.onclick = () => {
      chrome.management.setEnabled(highlightId, false, () => {
        addLog(`[System] Extension "${name}" disabled via real-time alert shield.`, 'system');
        alertBanner.classList.add('hide');
        performScan(); // Re-scan to update status
      });
    };

    alertDismissBtn.onclick = () => {
      alertBanner.classList.add('hide');
    };
  }
}

// Bind event listeners for management updates (auto refresh dashboard)
function setupManagementListeners() {
  const events = [
    chrome.management.onInstalled,
    chrome.management.onUninstalled,
    chrome.management.onEnabled,
    chrome.management.onDisabled
  ];
  
  events.forEach(evt => {
    evt.addListener((info) => {
      addLog(`[System] Browser extension list modified. Refreshing dashboard...`);
      performScan();
    });
  });
}

// Initializer
async function init() {
  setupManagementListeners();
  await loadWhitelist();
  const online = await checkHostConnection();
  await performScan();
  checkAlertQueries();
}

// Bind UI controls
runAuditBtn.addEventListener('click', performScan);
searchInput.addEventListener('input', renderExtensionsList);
sortSelect.addEventListener('change', renderExtensionsList);

// Launch
document.addEventListener('DOMContentLoaded', init);
