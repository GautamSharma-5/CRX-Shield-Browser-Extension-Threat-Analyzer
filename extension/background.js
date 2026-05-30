// CRX-Shield Background Service Worker
importScripts('trusted_extensions.js');

// Startup quiet window to prevent false alarms on browser launch
let systemInitialized = false;
setTimeout(() => {
  systemInitialized = true;
}, 5000);

// 1. Open dashboard when extension icon is clicked
chrome.action.onClicked.addListener(() => {
  chrome.tabs.create({ url: 'dashboard.html' });
});

// 2. Helper to scan a single extension via the Native Messaging Python host
function scanExtension(extId) {
  return new Promise((resolve) => {
    chrome.runtime.sendNativeMessage(
      'com.crx_shield.scanner',
      { action: 'scan', id: extId },
      (response) => {
        if (chrome.runtime.lastError) {
          // If Python host is not registered or not working, return a clear error
          resolve({
            status: 'error',
            id: extId,
            error: chrome.runtime.lastError.message
          });
        } else {
          resolve(response);
        }
      }
    );
  });
}

// 3. Handle messages from dashboard.js
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'scan_extension') {
    scanExtension(request.id).then((response) => {
      sendResponse(response);
    });
    return true; // Keep response channel open for async callback
  }
  
  if (request.action === 'get_all_extensions') {
    chrome.management.getAll((extensions) => {
      // Filter out CRX-Shield itself from the list of scanned extensions
      const ownId = chrome.runtime.id;
      const filtered = extensions.filter(ext => ext.id !== ownId);
      sendResponse(filtered);
    });
    return true;
  }
});

// 4. Real-time scanning for newly installed extensions
chrome.management.onInstalled.addListener((info) => {
  // Ignore when CRX-Shield itself is installed/updated
  if (info.id === chrome.runtime.id) return;

  // Prevent alerts for reloads/updates during browser startup quiet window
  if (!systemInitialized) {
    return;
  }

  // Let background complete loading, then run the scan
  setTimeout(() => {
    scanExtension(info.id).then((result) => {
      // 1. Run dynamic reputation check
      let isReputable = false;
      if (result && result.status === 'success' && result.reputation && result.reputation.status === 'success') {
        const rep = result.reputation;
        const meetThreshold = rep.users >= 50000 && rep.rating >= 4.0 && rep.reviews >= 100;
        
        // Ensure no High/Critical code threats are present (allow permission-based highs)
        const hasHighCodeThreats = result.findings && result.findings.some(f => 
          (f.severity === 'HIGH' || f.severity === 'CRITICAL') && f.category !== 'Permission'
        );
        
        if (meetThreshold && !hasHighCodeThreats) {
          isReputable = true;
        }
      }

      // 2. Ignore whitelisted and reputable extensions
      const isStaticWhitelisted = typeof TRUSTED_EXTENSIONS !== 'undefined' && TRUSTED_EXTENSIONS[info.id];
      if (isStaticWhitelisted || isReputable) {
        return;
      }

      if (result && result.status === 'success' && result.risk_score >= 70) {
        // High threat extension installed! Open dashboard and highlight the threat
        chrome.tabs.create({
          url: `dashboard.html?highlight=${info.id}&risk=${result.risk_score}&name=${encodeURIComponent(info.name)}`
        });
      }
    });
  }, 1000);
});
