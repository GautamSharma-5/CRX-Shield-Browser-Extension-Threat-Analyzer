import os
import sys
import json
import struct
import re
import zipfile
import urllib.request
import ssl

# Redirect print to stderr to prevent corrupting Chrome's stdout native messaging protocol
def log(message):
    sys.stderr.write(f"[Python Host] {message}\n")
    sys.stderr.flush()

# --- Native Messaging Protocol Helpers ---
def get_message():
    try:
        raw_length = sys.stdin.buffer.read(4)
        if not raw_length:
            log("No length header received, exiting.")
            return None
        message_length = struct.unpack('@I', raw_length)[0]
        message = sys.stdin.buffer.read(message_length).decode('utf-8')
        return json.loads(message)
    except Exception as e:
        log(f"Error reading message: {e}")
        return None

def send_message(message):
    try:
        encoded_message = json.dumps(message).encode('utf-8')
        sys.stdout.buffer.write(struct.pack('@I', len(encoded_message)))
        sys.stdout.buffer.write(encoded_message)
        sys.stdout.buffer.flush()
    except Exception as e:
        log(f"Error sending message: {e}")

# --- Extension Discovery Module ---
def locate_extension_folders(extension_id):
    """Locate the extension directories across Chrome, Edge, Brave, and Firefox on Windows."""
    paths = []
    local_app_data = os.environ.get('LOCALAPPDATA', '')
    app_data = os.environ.get('APPDATA', '')

    # 1. Chromium Browsers (Chrome, Edge, Brave)
    if local_app_data:
        chromium_configs = {
            'Chrome': os.path.join(local_app_data, 'Google', 'Chrome', 'User Data'),
            'Edge': os.path.join(local_app_data, 'Microsoft', 'Edge', 'User Data'),
            'Brave': os.path.join(local_app_data, 'BraveSoftware', 'Brave-Browser', 'User Data')
        }

        for browser_name, user_data_path in chromium_configs.items():
            if os.path.isdir(user_data_path):
                # Scan all profiles (Default, Profile 1, Profile 2, etc.)
                for profile in os.listdir(user_data_path):
                    profile_path = os.path.join(user_data_path, profile)
                    if os.path.isdir(profile_path):
                        ext_path = os.path.join(profile_path, 'Extensions', extension_id)
                        if os.path.isdir(ext_path):
                            # Find all version folders (usually just one, but scan all)
                            for version in os.listdir(ext_path):
                                version_path = os.path.join(ext_path, version)
                                if os.path.isdir(version_path):
                                    paths.append({
                                        'browser': browser_name,
                                        'profile': profile,
                                        'path': version_path,
                                        'type': 'dir'
                                    })

    # 2. Mozilla Firefox
    if app_data:
        firefox_profiles = os.path.join(app_data, 'Mozilla', 'Firefox', 'Profiles')
        if os.path.isdir(firefox_profiles):
            for profile in os.listdir(firefox_profiles):
                profile_path = os.path.join(firefox_profiles, profile)
                ext_dir = os.path.join(profile_path, 'extensions')
                if os.path.isdir(ext_dir):
                    # In Firefox, extension ID can match the filename (e.g. extension_id.xpi or extension_id directory)
                    for item in os.listdir(ext_dir):
                        if extension_id in item:
                            item_path = os.path.join(ext_dir, item)
                            if os.path.isfile(item_path) and item.endswith('.xpi'):
                                paths.append({
                                    'browser': 'Firefox',
                                    'profile': profile,
                                    'path': item_path,
                                    'type': 'xpi'
                                })
                            elif os.path.isdir(item_path):
                                paths.append({
                                    'browser': 'Firefox',
                                    'profile': profile,
                                    'path': item_path,
                                    'type': 'dir'
                                })
    return paths

# --- Static Analysis Heuristics Engine ---
def analyze_manifest_dict(manifest):
    """Scan parsed manifest data for permission risks."""
    findings = []
    risk_score = 0

    permissions = manifest.get('permissions', [])
    optional_permissions = manifest.get('optional_permissions', [])
    host_permissions = manifest.get('host_permissions', [])
    
    all_permissions = set(permissions + optional_permissions)
    
    # Check for broad Host Permissions (access to all websites)
    has_all_urls = False
    for hp in host_permissions:
        if hp in ['<all_urls>', '*://*/*', 'http://*/*', 'https://*/*']:
            has_all_urls = True
            
    for p in permissions:
        if p in ['<all_urls>', '*://*/*', 'http://*/*', 'https://*/*'] or p.startswith('http') or p.startswith('*'):
            has_all_urls = True
            
    if has_all_urls:
        risk_score += 30
        findings.append({
            'severity': 'HIGH',
            'category': 'Permission',
            'desc': 'Requests access to read/modify data on all websites you visit (broad host access).'
        })

    # Sensitive Extension API checks
    sensitive_apis = {
        'webRequest': ('MEDIUM', 'Can inspect network requests (used by ad-blockers, but can steal request headers/credentials).', 15),
        'webRequestBlocking': ('HIGH', 'Can block/modify network requests synchronously, allowing request hijacking.', 20),
        'cookies': ('MEDIUM', 'Can read and write browser cookies, which can lead to session hijacking / MFA bypass.', 15),
        'debugger': ('CRITICAL', 'Can attach debugger to tabs, giving full execution control and bypassing browser security.', 35),
        'proxy': ('HIGH', 'Can route all browser traffic through an external server, intercepting web requests.', 25),
        'declarativeNetRequest': ('MEDIUM', 'Can intercept and modify headers/requests without full webRequest overhead.', 10),
        'management': ('MEDIUM', 'Can manage other extensions, meaning it can disable security or antivirus extensions.', 15),
        'scripting': ('MEDIUM', 'Can inject arbitrary external code execution scripts into any tab.', 15)
    }

    for api, (severity, desc, score) in sensitive_apis.items():
        if api in all_permissions:
            risk_score += score
            findings.append({
                'severity': severity,
                'category': 'Permission',
                'desc': f'Requests sensitive API permission "{api}": {desc}'
            })

    return risk_score, findings

def analyze_js_code(code_content, file_name):
    """Scan JavaScript code content for indicators of malicious behaviors."""
    findings = []
    score = 0

    # 1. Dynamic Code Execution
    if 'eval(' in code_content or 'new Function(' in code_content or 'setTimeout(' in code_content and ',' not in code_content:
        score += 20
        findings.append({
            'severity': 'HIGH',
            'category': 'Heuristic',
            'desc': f'Dynamic code execution (`eval()` or `new Function()`) found in `{file_name}`.'
        })

    # 2. Obfuscation detection
    hex_escapes = code_content.count('\\x')
    if hex_escapes > 30 and (hex_escapes / max(1, len(code_content))) > 0.005:
        score += 25
        findings.append({
            'severity': 'HIGH',
            'category': 'Obfuscation',
            'desc': f'High density of hex-escaped text inside `{file_name}` (common in obfuscated malware).'
        })
    elif 'window["\\x' in code_content or 'globalThis["\\x' in code_content:
        score += 25
        findings.append({
            'severity': 'HIGH',
            'category': 'Obfuscation',
            'desc': f'Obfuscated window property access in `{file_name}`.'
        })

    # 3. Spyware: Keystroke monitoring
    if ('keydown' in code_content or 'keypress' in code_content or 'keyup' in code_content) and ('.value' in code_content or 'target.value' in code_content):
        score += 30
        findings.append({
            'severity': 'HIGH',
            'category': 'Spyware',
            'desc': f'Key-logger heuristic: key event listener capturing input values in `{file_name}`.'
        })

    # 4. Spyware: Password field scraping
    if 'password' in code_content.lower() and ('querySelector' in code_content or 'getElementById' in code_content) and '.value' in code_content:
        score += 25
        findings.append({
            'severity': 'HIGH',
            'category': 'Spyware',
            'desc': f'Credential harvester heuristic: code searches for password fields and extracts values in `{file_name}`.'
        })

    # 5. Suspicious Communications
    if 'fetch(' in code_content or 'XMLHttpRequest' in code_content or 'WebSocket(' in code_content:
        # Check if there are external URL patterns
        urls = re.findall(r'https?://[^\s\'"]+', code_content)
        # Filter out common safe browser domains
        external_urls = [u for u in urls if not any(domain in u for domain in ['google.com', 'mozilla.org', 'chrome-extension', 'github.com'])]
        if external_urls:
            score += 15
            findings.append({
                'severity': 'MEDIUM',
                'category': 'Network',
                'desc': f'External communication endpoint found in `{file_name}` (e.g. `{external_urls[0][:40]}...`).'
            })

    return score, findings

def analyze_directory(directory_path):
    """Scan an unpacked extension directory."""
    manifest_path = os.path.join(directory_path, 'manifest.json')
    if not os.path.exists(manifest_path):
        return 10, [{'severity': 'LOW', 'category': 'Manifest', 'desc': 'Manifest file not found in directory.'}]

    try:
        with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
            manifest = json.load(f)
    except Exception as e:
        return 20, [{'severity': 'MEDIUM', 'category': 'Manifest', 'desc': f'Failed to parse manifest.json: {str(e)}'}]

    risk_score, findings = analyze_manifest_dict(manifest)

    # Walk directory to find and analyze JS files
    for root, _, files in os.walk(directory_path):
        for file in files:
            if file.endswith('.js'):
                js_path = os.path.join(root, file)
                # Skip massive library files
                if os.path.getsize(js_path) > 300000:
                    continue
                try:
                    with open(js_path, 'r', encoding='utf-8', errors='ignore') as f:
                        code = f.read()
                    js_score, js_findings = analyze_js_code(code, file)
                    risk_score += js_score
                    findings.extend(js_findings)
                except Exception:
                    pass

    risk_score = min(risk_score, 100)
    return max(risk_score, 5), findings

def analyze_xpi_archive(xpi_path):
    """Scan a Firefox zipped .xpi extension file in-memory."""
    if not zipfile.is_zipfile(xpi_path):
        return 10, [{'severity': 'LOW', 'category': 'Archive', 'desc': 'Not a valid ZIP/XPI archive.'}]

    try:
        with zipfile.ZipFile(xpi_path, 'r') as zf:
            if 'manifest.json' not in zf.namelist():
                return 15, [{'severity': 'MEDIUM', 'category': 'Manifest', 'desc': 'manifest.json not found in XPI.'}]

            manifest_content = zf.read('manifest.json').decode('utf-8', errors='ignore')
            manifest = json.loads(manifest_content)
            risk_score, findings = analyze_manifest_dict(manifest)

            # Analyze JS files inside zip
            for filename in zf.namelist():
                if filename.endswith('.js'):
                    info = zf.getinfo(filename)
                    if info.file_size > 300000:
                        continue
                    try:
                        code = zf.read(filename).decode('utf-8', errors='ignore')
                        js_score, js_findings = analyze_js_code(code, os.path.basename(filename))
                        risk_score += js_score
                        findings.extend(js_findings)
                    except Exception:
                        pass

            risk_score = min(risk_score, 100)
            return max(risk_score, 5), findings
    except Exception as e:
        return 20, [{'severity': 'MEDIUM', 'category': 'Archive', 'desc': f'Failed to parse XPI file: {str(e)}'}]

# --- dynamic OSINT Reputation Module ---
def fetch_chrome_web_store_reputation(extension_id):
    """Fetch rating, review count, and user count dynamically from Chrome Web Store."""
    # Skip for ping or invalid formatted IDs
    if len(extension_id) != 32:
        return {'status': 'error', 'error': 'Invalid Extension ID format.'}

    url = f"https://chromewebstore.google.com/detail/{extension_id}"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept-Language': 'en-US,en;q=0.9'
    }
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    try:
        log(f"Fetching reputation from CWS for ID: {extension_id}...")
        req = urllib.request.Request(url, headers=headers)
        # Timeout after 3 seconds to avoid blocking the scanner indefinitely
        with urllib.request.urlopen(req, context=ctx, timeout=3) as response:
            html = response.read().decode('utf-8')
            
        # Search for key: 'ds:0' data payload using regex
        match = re.search(r"key:\s*'ds:0'.*?data:\s*(\[.*?\])\s*,\s*sideChannel:", html, re.DOTALL)
        if match:
            data = json.loads(match.group(1))
            if data and len(data) > 0:
                info = data[0]
                if len(info) > 14:
                    name = info[2]
                    rating = info[3]
                    reviews = info[4]
                    users = info[14]
                    
                    return {
                        'status': 'success',
                        'name': name,
                        'rating': float(rating) if rating is not None else 0.0,
                        'reviews': int(reviews) if reviews is not None else 0,
                        'users': int(users) if users is not None else 0
                    }
        return {'status': 'not_found', 'error': 'Could not parse Web Store payload.'}
    except Exception as e:
        log(f"Failed to fetch reputation for {extension_id}: {e}")
        return {'status': 'error', 'error': str(e)}

# --- Main Dispatcher ---
def main():
    log("CRX-Shield Native Scanner active and waiting...")
    while True:
        msg = get_message()
        if msg is None:
            break

        action = msg.get('action')
        ext_id = msg.get('id')

        if not ext_id:
            send_message({'status': 'error', 'error': 'No extension ID provided.'})
            continue

        if action in ['scan', 'scan_one']:
            log(f"Received scan request for extension ID: {ext_id}")
            paths = locate_extension_folders(ext_id)
            
            # Fetch CWS reputation in parallel/sequence
            reputation = fetch_chrome_web_store_reputation(ext_id)
            
            if not paths:
                # Could not locate files, return baseline report with reputation if available
                send_message({
                    'status': 'not_found',
                    'id': ext_id,
                    'risk_score': 0,
                    'findings': [{'severity': 'INFO', 'category': 'Environment', 'desc': 'Unpacked/local source files not found (extension might be built-in or profile path custom).'}],
                    'install_locations': [],
                    'reputation': reputation
                })
                continue

            # Analyze the located installation folders
            primary_path = paths[0]
            if primary_path['type'] == 'dir':
                score, findings = analyze_directory(primary_path['path'])
            else:
                score, findings = analyze_xpi_archive(primary_path['path'])

            locations = [{'browser': p['browser'], 'profile': p['profile'], 'path': p['path']} for p in paths]

            send_message({
                'status': 'success',
                'id': ext_id,
                'risk_score': score,
                'findings': findings,
                'install_locations': locations,
                'reputation': reputation
            })

if __name__ == '__main__':
    main()
