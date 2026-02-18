# IntelliScan

IntelliScan is a lightweight Flask web application for authorized network assessment and security learning. It performs basic port discovery, enriches scan results with threat-intelligence signals (e.g., AbuseIPDB-style reputation checks), assigns a simple risk level, and generates readable HTML reports saved under `reports/`.


## Features

- Web dashboard to start scans and review results
- Port scanning with configurable options (based on implementation)
- Threat-intelligence enrichment (reputation/confidence signals and metadata where available)
- Risk scoring (Low / Medium / High) to help prioritize findings
- Automatic HTML report generation stored in `reports/`
- Optional Docker/Nmap support for deeper scanning workflows

## Project Structure

```text
.
├── intelliscan.py
├── Dockerfile
├── templates/
│   └── index.html
├── static/
│   ├── script.js
│   └── css/
│       └── style.css
└── reports/
    └── scan_report_*.html
Requirements
Python 3.9+ (recommended)

pip

(Optional) Docker

Installation
Clone the repository and install dependencies:

git clone https://github.com/<arunparihar001>/<IntelliScan-Advanced-Network-Security-Scanner>.git
cd <IntelliScan-Advanced-Network-Security-Scanner>
python -m venv .venv
Activate the virtual environment:

Windows (PowerShell)

.venv\Scripts\activate
macOS/Linux

source .venv/bin/activate
Install dependencies:

pip install -r requirements.txt
If you do not have a requirements.txt yet:

pip install flask requests
Configuration
If threat-intelligence lookups require an API key, do not hardcode it in the source code. Set it as an environment variable instead.

Example:

ABUSEIPDB_API_KEY

Windows (PowerShell):

setx ABUSEIPDB_API_KEY "YOUR_KEY_HERE"
macOS/Linux:

export ABUSEIPDB_API_KEY="YOUR_KEY_HERE"
Running the Application
Start the server:

python intelliscan.py
Open the application in your browser:

http://127.0.0.1:5000

Reports
Generated scan reports are saved as HTML files under:

reports/scan_report_<target>.html

Docker (Optional)
Build the image:

docker build -t intelliscan .
Run the container:

docker run -p 5000:5000 -e ABUSEIPDB_API_KEY="YOUR_KEY_HERE" intelliscan
Then open:

http://127.0.0.1:5000
