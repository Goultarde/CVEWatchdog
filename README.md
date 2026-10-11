# CVEWatchdog 🔍

**CVEWatchdog** is a cross-platform vulnerability scanner client for [FastCVE-API](https://github.com/CobblePot59/FastCVE-API) that identifies CVEs (Common Vulnerabilities and Exposures) on installed software.

## 🚀 Features

- **Automated scanning** of installed software
- **Centralized CPE resolution** through FastCVE-API
- **NVD version-range matching** before a CVE is reported
- **Detailed CVE reports** with CVSS scores and severity levels
- **Explicit unresolved/API-error reporting** in debug mode
- **Comprehensive summary** with overall risk assessment
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
```

## 📊 Output

The script generates a structured report with:

- **Vulnerable software list** with detailed CVE information
- **CVE table** containing:
  - CVE ID
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

Both clients send the installed display name and version to `POST /api/resolve`. FastCVE-API owns CPE selection and version applicability, so the Python and PowerShell clients use the same matching rules. A resolved product with no CVE is kept distinct from an unresolved product or an API failure.

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
