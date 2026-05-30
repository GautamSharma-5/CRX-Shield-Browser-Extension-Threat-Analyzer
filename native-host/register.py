import os
import sys
import json
import winreg
def register_host():
    current_dir = os.path.abspath(os.path.dirname(__file__))
    manifest_path = os.path.join(current_dir, 'com.crx_shield.scanner.json')
    bat_path = os.path.join(current_dir, 'host.bat')
    extension_dir = os.path.abspath(os.path.join(current_dir, '..', 'extension'))
    ext_manifest_path = os.path.join(extension_dir, 'manifest.json')
    print("==================================================")
    print("      CRX-Shield Native Host Auto-Register        ")
    print("==================================================")
    extension_id = ""
    if os.path.exists(ext_manifest_path):
        try:
            with open(ext_manifest_path, 'r', encoding='utf-8') as f:
                manifest_data = json.load(f)
        except Exception:
            pass
    print("\nTo hook the scanner to Chrome/Edge, we need your Extension ID.")
    print("1. Go to chrome://extensions/ in your browser.")
    print("2. Enable 'Developer mode' (top right toggle).")
    print("3. Load the unpacked 'extension' folder.")
    print("4. Copy the Extension ID (32-character string).")
    user_id = input("\nEnter Extension ID (or press Enter if not loaded yet): ").strip()
    if user_id:
        extension_id = user_id
    else:
        extension_id = "coobgdehopoocjebjcbjceanbggn... (replace this)"
        print("Using placeholder extension ID. You can re-run this script later to update the ID.")
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            data['path'] = bat_path
            if extension_id:
                data['allowed_origins'] = [f"chrome-extension://{extension_id}/"]
            with open(manifest_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            print(f"\n[+] Updated native host manifest at: {manifest_path}")
            print(f"    - Executable Path: {bat_path}")
            print(f"    - Allowed Origin: chrome-extension://{extension_id}/")
        except Exception as e:
            print(f"[-] Error updating manifest file: {e}")
            sys.exit(1)
    else:
        print(f"[-] Manifest file not found at: {manifest_path}")
        sys.exit(1)
    registry_paths = {
        "Google Chrome": r"Software\Google\Chrome\NativeMessagingHosts\com.crx_shield.scanner",
        "Microsoft Edge": r"Software\Microsoft\Edge\NativeMessagingHosts\com.crx_shield.scanner",
        "Brave Browser": r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\com.crx_shield.scanner",
        "Mozilla Firefox": r"Software\Mozilla\NativeMessagingHosts\com.crx_shield.scanner"
    }
    print("\nRegistering Native Messaging Host in Windows Registry...")
    for browser, reg_path in registry_paths.items():
        try:
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_path)
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, manifest_path)
            winreg.CloseKey(key)
            print(f"  [+] Registered for {browser}")
        except Exception as e:
            print(f"  [-] Failed to register for {browser}: {e}")
    print("\n[+] Registration Completed successfully!")
    print("==================================================")
if __name__ == '__main__':
    register_host()
