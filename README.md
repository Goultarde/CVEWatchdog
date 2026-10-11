# CVEWatchdog 🔍

**CVEWatchdog** is a cross-platform vulnerability scanner client for [FastCVE-API](https://github.com/CobblePot59/FastCVE-API) that identifies CVEs (Common Vulnerabilities and Exposures) on installed software.

## 🚀 Features

- **Automated scanning** of installed software
- **Centralized CPE resolution** through FastCVE-API
- **NVD version-range matching** before a CVE is reported
- **Detailed CVE reports** with CVSS scores and severity levels
- **Explicit unresolved/API-error reporting** in debug mode
- **Comprehensive summary** with overall risk assessment
- **Standalone filterable HTML reports** for sharing and archiving scan results
- **Cross-platform support** (Windows & Linux)

## 📋 Requirements

### Windows

- **PowerShell 5.0+** (Windows 10/11 or Server 2016+)
- **FastCVE-API** service running locally on port 8001 or accessible on your network
- Administrator access to read Windows Registry

### Linux

- **Python 3.8+**
- **FastCVE-API** service running locally on port 8001 or accessible on your network
- Root or sudo access to read package information
- **Supported package managers:**
  - dpkg (Debian/Ubuntu)
  - rpm (RedHat/Fedora/CentOS)
  - pacman (Arch Linux)
  - apk (Alpine Linux)

## 🛠️ Installation

### Windows

```bash
# Clone the repository
git clone https://github.com/CobblePot59/CVEWatchdog.git
cd CVEWatchdog

# Set execution policy to allow script execution
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Linux

```bash
# Clone the repository
git clone https://github.com/CobblePot59/CVEWatchdog.git
cd CVEWatchdog

# Install the Python client
pipx install .

# Update an existing installation
pipx upgrade cvewatchdog
```

## 🎯 Usage

Install and start FastCVE-API before running the scanner:

```bash
cd ../FastCVE-API
pipx install .
fastcve-api --data-path "$PWD/data"
```

Then check it from another terminal:

```bash
curl http://localhost:8001/health
```

The first API startup downloads and indexes the NVD datasets. Wait until `/health` returns JSON before starting CVEWatchdog.

### Windows

Basic usage:
```powershell
.\CVEWatchdog.ps1
```

Advanced options:
```powershell
# Show CPE resolution details
.\CVEWatchdog.ps1  -ApiUrl http://localhost:8001 -DebugMatching

# Specify custom API URL
.\CVEWatchdog.ps1 -ApiUrl "http://<IP_DU_SERVEUR>:8001"
```

### Linux

Basic usage:
```bash
cvewatchdog
```

Advanced options:
```bash
# Show the selected CPE and confidence score
cvewatchdog http://localhost:8001 --debug

# Specify custom API URL
cvewatchdog http://<IP_DU_SERVEUR>:8001

# Generate a standalone HTML report
cvewatchdog http://localhost:8001 --html-report cvewatchdog-report.html
```

The HTML report can be filtered locally by software, CPE, CVE, CWE, description, severity,
or inferred vulnerability type (LPE, RCE, privilege escalation, DoS, information
disclosure, authentication bypass, XSS, SQL injection, or path traversal).
The CWE selector includes weakness names from the bundled MITRE CWE catalog.
Its opening software list shows the number of CVEs per vulnerable application and
can display all, none, one, or any selected combination of applications.

## 📊 Output

The script generates a structured report with:

- **Vulnerable software list** with detailed CVE information
- **CVE table** containing:
  - CVE ID
  - CWE identifiers
  - Severity level (Critical/High/Medium/Low)
  - CVSS Score
  - Affected version
  - Publication date
  - Description

- **Summary** with:
  - Total CVEs found
  - Breakdown by severity
  - Overall risk assessment (🟢 LOW / 🟡 MEDIUM / 🔴 HIGH / ⚫ CRITICAL)

Wildcard CPE entries are evaluated by FastCVE-API together with their NVD version bounds. The legacy `-Wildcards`/`--wildcards` option is still accepted for command compatibility but is no longer needed.

## How matching works

Both clients send the installed display name, version, platform, and available publisher/URL metadata to `POST /api/resolve`. FastCVE-API requires an exact, unambiguous CPE product match and only keeps NVD entries with explicit version and platform evidence. A resolved product with no CVE is kept distinct from an unresolved product or an API failure.

## Tests

Python client:

```bash
python3 -m unittest discover -s tests -v
```

PowerShell client (requires Pester 5):

```powershell
Invoke-Pester .\tests\CVEWatchdog.Tests.ps1
```

![CVEWatchdog.png](.github/pictures/CVEWatchdog.png)

## 🤝 Contributing

Contributions are welcome!
