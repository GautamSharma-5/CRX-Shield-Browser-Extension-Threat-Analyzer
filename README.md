# 🛡️ CRX-Shield: Browser Extension Threat Analyzer

**CRX-Shield** is a powerful, hybrid browser security tool designed to protect users from malicious and suspicious browser extensions. It operates entirely on your local machine, bridging the gap between browser sandboxing and deep static code analysis.

## 🌟 Features

- **Real-Time Monitoring:** Detects when a new extension is installed or updated.
- **Deep Static Analysis:** Parses `manifest.json` for excessive permissions and scans JavaScript files (`.js`) for suspicious patterns using a heuristic regex engine.
- **Privacy First:** 100% local analysis. No extension data or browsing history is ever sent to the cloud.
- **Native Messaging Architecture:** Utilizes standard Native Messaging APIs to communicate securely between the WebExtension frontend and the Python backend.

## 🏗️ Architecture

CRX-Shield utilizes a dual-component architecture to overcome the strict sandboxing limitations of modern web browsers:

1. **Frontend (WebExtension - Manifest V3):** A lightweight browser extension that provides a user-friendly dashboard to view the security status of your installed extensions and intercept new installations.
2. **Backend (Python Native Host):** A Python script running on your local OS that traverses extension directories, unpacks files if necessary, and performs the heavy-lifting static analysis.

### System Flow
![Flowchart](Flowchart%20Diagram.png)

### Data Boundary
![Data Flow](Data%20Flow%20Diagram.png)

## 🚀 Installation & Setup

### Prerequisites
- Python 3.10 or higher
- Google Chrome, Microsoft Edge, or Mozilla Firefox

### Step 1: Set up the Python Backend
1. Clone or download this repository.
2. Navigate to the `native-host` directory in your terminal or command prompt.
3. Run the setup script to register the Native Messaging host with your browser:
   ```bash
   python register.py
   ```
   *(This script securely adds the necessary entries to your local registry/configuration so the browser knows where to find the Python host).*

### Step 2: Load the Frontend Extension
1. Open your browser and navigate to the extensions page (e.g., `chrome://extensions/` or `edge://extensions/`).
2. Enable **Developer mode** in the top right corner.
3. Click **Load unpacked** and select the `extension` folder from this repository.
4. Pin the CRX-Shield icon to your toolbar to access the dashboard!

## 🧠 How It Works

1. **Trigger:** When you install a new extension, the CRX-Shield WebExtension extracts its unique ID.
2. **Communication:** It sends this ID through a securely established **Native Messaging Pipe** (standard I/O streams).
3. **Execution:** The Python Host receives the ID, locates the unpacked extension files on your hard drive, and begins the audit.
4. **Analysis:** It evaluates permission severity (e.g., `<all_urls>`, `cookies`) and scans the source code for obfuscation, dynamic evaluation (e.g., `eval()`), and data harvesting APIs.
5. **Result:** A **Risk Score** is calculated and sent back to the frontend, instantly alerting you if the extension is deemed a threat.

### Component Interaction Timeline
![UML Sequence Diagram](UML%20Diagram.png)

## 🤝 Contributing
Contributions, issues, and feature requests are welcome! Feel free to check the issues page.

## 📜 About
This project was originally developed as an academic dissertation focusing on localized cybersecurity threat mitigation.
# CRX-Shield-Browser-Extension-Threat-Analyzer
