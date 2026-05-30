
importScripts('trusted_extensions.js');
let systemInitialized = false;
setTimeout(() => {
  systemInitialized = true;
}, 5000);
chrome.action.onClicked.addListener(() => {
  chrome.tabs.create({ url: 'dashboard.html' });
});
function scanExtension(extId) {
  return new Promise((resolve) => {
    chrome.runtime.sendNativeMessage(
      'com.crx_shield.scanner',
      { action: 'scan', id: extId },
      (response) => {
        if (chrome.runtime.lastError) {
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
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'scan_extension') {
    scanExtension(request.id).then((response) => {
      sendResponse(response);
    });
    return true;
  }
  if (request.action === 'get_all_extensions') {
    chrome.management.getAll((extensions) => {
      const ownId = chrome.runtime.id;
      const filtered = extensions.filter(ext => ext.id !== ownId);
      sendResponse(filtered);
    });
    return true;
  }
});
chrome.management.onInstalled.addListener((info) => {
  if (info.id === chrome.runtime.id) return;
  if (!systemInitialized) {
    return;
  }
  setTimeout(() => {
    scanExtension(info.id).then((result) => {
      let isReputable = false;
      if (result && result.status === 'success' && result.reputation && result.reputation.status === 'success') {
        const rep = result.reputation;
        const meetThreshold = rep.users >= 50000 && rep.rating >= 4.0 && rep.reviews >= 100;
        const hasHighCodeThreats = result.findings && result.findings.some(f => 
          (f.severity === 'HIGH' || f.severity === 'CRITICAL') && f.category !== 'Permission'
        );
        if (meetThreshold && !hasHighCodeThreats) {
          isReputable = true;
        }
      }
      const isStaticWhitelisted = typeof TRUSTED_EXTENSIONS !== 'undefined' && TRUSTED_EXTENSIONS[info.id];
      if (isStaticWhitelisted || isReputable) {
        return;
      }
      if (result && result.status === 'success' && result.risk_score >= 70) {
        chrome.tabs.create({
          url: `dashboard.html?highlight=${info.id}&risk=${result.risk_score}&name=${encodeURIComponent(info.name)}`
        });
      }
    });
  }, 1000);
});
