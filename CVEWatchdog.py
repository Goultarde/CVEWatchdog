import argparse
import html
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
import requests
from cwe_names import CWE_NAMES

CVSS_LEVELS = {
    "Critical": 9.0,
    "High": 7.0,
    "Medium": 4.0,
    "Low": 0.1
}

PLATFORM = "windows" if sys.platform.startswith("win") else "macos" if sys.platform == "darwin" else "linux"

# ANSI color codes
class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    GRAY = '\033[90m'
    BLACK = '\033[90m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class Software:
    def __init__(self, name, version, context=""):
        self.name = name
        self.version = version
        self.context = context

def parse_pacman_inventory(output):
    software = []
    for record in output.split("\n\n"):
        fields = {}
        for line in record.splitlines():
            if ":" in line and not line.startswith(" "):
                key, value = line.split(":", 1)
                fields[key.strip()] = value.strip()
        if fields.get("Name") and fields.get("Version"):
            version = fields["Version"].split(":", 1)[-1].split("-", 1)[0]
            context = " ".join(
                fields.get(key, "") for key in ("Description", "URL", "Packager")
            )
            software.append(Software(fields["Name"], version, context))
    return software

def get_installed_software():
    """Scan installed software packages on Linux"""
    print(f"{Colors.CYAN}📦 Scanning installed software...{Colors.RESET}")
    
    software = []
    ignored = 0
    
    # Try different package managers
    package_managers = [
        ("dpkg", ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Maintainer}\t${Homepage}\n"]),
        ("rpm", ["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}\t%{VENDOR}\t%{URL}\n"]),
        ("pacman", ["pacman", "-Qi"]),
        ("apk", ["apk", "info", "-v"])
    ]
    
    for pm_name, command in package_managers:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=10,
                env={**os.environ, "LC_ALL": "C"},
            )
            
            if result.returncode == 0:
                if pm_name == "pacman":
                    software = parse_pacman_inventory(result.stdout)
                    if software:
                        print(f"{Colors.GREEN}✅ Found {len(software)} packages using pacman "
                              f"(ignoring {ignored} system packages){Colors.RESET}")
                        return software, ignored
                    continue

                lines = result.stdout.strip().split('\n')
                
                for line in lines:
                    if not line.strip():
                        continue
                    
                    parts = line.split('\t') if '\t' in line else line.split()
                    if len(parts) >= 2:
                        name = parts[0].strip()
                        version = parts[1].strip()
                        
                        # Remove architecture suffix (e.g., :amd64)
                        if ':' in name:
                            name = name.split(':')[0]
                        
                        # Remove epoch from version (e.g., 1:2.3.4)
                        if ':' in version:
                            version = version.split(':', 1)[1]
                        
                        # Remove release suffix (e.g., -1ubuntu1)
                        version = version.split('-')[0]
                        
                        # Ignore kernel and core system packages
                        ignore_patterns = []
                        
                        if any(pattern in name.lower() for pattern in ignore_patterns):
                            ignored += 1
                            continue
                        
                        software.append(Software(
                            name=name,
                            version=version,
                            context=" ".join(parts[2:]),
                        ))
                
                if software:
                    print(f"{Colors.GREEN}✅ Found {len(software)} packages using {pm_name} "
                          f"(ignoring {ignored} system packages){Colors.RESET}")
                    return software, ignored
                
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
            continue
    
    print(f"{Colors.RED}❌ No supported package manager found (dpkg, rpm, pacman, apk){Colors.RESET}")
    sys.exit(1)

def resolve_software(api_url, software_name, version, context="", platform_name=PLATFORM):
    """Resolve software to a CPE and applicable CVEs through FastCVE-API."""
    response = requests.post(
        f"{api_url.rstrip('/')}/api/resolve",
        json={
            "software": software_name,
            "version": version,
            "context": context,
            "platform": platform_name,
        },
        timeout=10,
    )
    response.raise_for_status()
    return response.json()

def get_cvss_severity(score):
    """Get severity level from CVSS score"""
    if score is None:
        return "Unknown"
    if score >= CVSS_LEVELS["Critical"]:
        return "Critical"
    elif score >= CVSS_LEVELS["High"]:
        return "High"
    elif score >= CVSS_LEVELS["Medium"]:
        return "Medium"
    elif score >= CVSS_LEVELS["Low"]:
        return "Low"
    return "None"

def classify_vulnerability(description):
    """Infer broad vulnerability types from the NVD description."""
    text = description.casefold()
    types = []
    privilege = bool(re.search(
        r"(?:escalat|elevat|gain|obtain)\w*(?:\s+\w+){0,3}\s+privileg|"
        r"gain(?:\s+\w+){0,2}\s+root|root privileg",
        text,
    ))
    local = any(term in text for term in ("local attacker", "local user", "local users", "locally"))
    explicit_lpe = any(term in text for term in (
        "local privilege escalation", "local privilege elevation",
        "local escalation of privilege", "local elevation of privilege",
    ))
    if explicit_lpe or (privilege and local):
        types.append(("lpe", "LPE"))
    elif privilege:
        types.append(("privilege-escalation", "Privilege escalation"))
    remote = any(term in text for term in (
        "remote attacker", "remote attackers", "remote user", "network attacker", "remotely",
    ))
    code_execution = any(term in text for term in (
        "execute arbitrary code", "execution of arbitrary code", "arbitrary code execution",
    ))
    if "remote code execution" in text or (remote and code_execution):
        types.append(("rce", "RCE"))
    if any(term in text for term in ("denial of service", "denial-of-service")):
        types.append(("dos", "DoS"))
    if any(term in text for term in ("information disclosure", "information leak", "sensitive information")):
        types.append(("information-disclosure", "Information disclosure"))
    if any(term in text for term in ("authentication bypass", "bypass authentication")):
        types.append(("authentication-bypass", "Authentication bypass"))
    if "cross-site scripting" in text or " xss " in f" {text} ":
        types.append(("xss", "XSS"))
    if "sql injection" in text:
        types.append(("sql-injection", "SQL injection"))
    if any(term in text for term in ("path traversal", "directory traversal")):
        types.append(("path-traversal", "Path traversal"))
    return types or [("other", "Other")]

def format_cve_table(cves):
    """Format CVE data as a table"""
    if not cves:
        return
    
    print(f"\n{'CVE ID':<20} {'Severity':<12} {'CVSS':<8} {'Version':<15} {'Published':<12} {'Description':<50}")
    print("─" * 120)
    
    for cve in cves:
        severity = get_cvss_severity(cve.get('cvss_score'))
        cvss_str = f"{cve.get('cvss_score', 0):.1f}" if cve.get('cvss_score') else "N/A"
        published = cve.get('published', '').split('T')[0]
        description = cve.get('description', '')
        
        if len(description) > 50:
            description = description[:47] + "..."
        
        # Color code severity
        severity_color = Colors.RESET
        if severity == "Critical":
            severity_color = Colors.BLACK
        elif severity == "High":
            severity_color = Colors.RED
        elif severity == "Medium":
            severity_color = Colors.YELLOW
        elif severity == "Low":
            severity_color = Colors.GREEN
        
        print(f"{cve.get('cve_id', ''):<20} {severity_color}{severity:<12}{Colors.RESET} "
              f"{cvss_str:<8} {cve.get('version', ''):<15} {published:<12} {description:<50}")

def run_sploitscan(cves, progress_callback=None):
    """Run the optional SploitScan CLI once and index its JSON results by CVE ID."""
    cve_ids = list(dict.fromkeys(
        str(cve.get("cve_id", "")).upper() for cve in cves
        if re.fullmatch(r"CVE-\d{4}-\d{4,7}", str(cve.get("cve_id", "")), re.IGNORECASE)
    ))
    if not cve_ids:
        return {}

    executable = shutil.which("sploitscan")
    if not executable:
        raise RuntimeError("SploitScan is not installed; run: pipx install sploitscan")
    command = [executable]
    try:
        shebang = Path(executable).read_text(encoding="utf-8").splitlines()[0]
        launcher = shlex.split(shebang[2:]) if shebang.startswith("#!") else []
        if launcher and Path(launcher[0]).name.lower().startswith("python"):
            command = [launcher[0], "-u", executable]
    except (OSError, UnicodeError, ValueError, IndexError):
        pass

    with tempfile.TemporaryDirectory() as directory:
        import_path = Path(directory) / "cves.txt"
        import_path.write_text("\n".join(cve_ids), encoding="utf-8")
        try:
            process = subprocess.Popen(
                command + ["--import-file", str(import_path), "--export", "json",
                 "--methods", "cisa,epss,prio"],
                cwd=directory,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env={
                    **os.environ,
                    "PYTHONIOENCODING": "utf-8",
                    "PYTHONUNBUFFERED": "1",
                },
            )
        except FileNotFoundError as error:
            raise RuntimeError("SploitScan is not installed; run: pipx install sploitscan") from error
        output = []
        processed = set()
        for line in process.stdout:
            output.append(line)
            match = re.search(r"CVE ID:\s*(CVE-\d{4}-\d{4,7})", line, re.IGNORECASE)
            if match and match.group(1).upper() not in processed:
                cve_id = match.group(1).upper()
                processed.add(cve_id)
                if progress_callback:
                    progress_callback(cve_id)
        return_code = process.wait()
        output = "".join(output)
        if return_code:
            detail = output.strip().splitlines()
            raise RuntimeError(detail[-1] if detail else "SploitScan failed")
        match = re.search(r"Data exported to file:\s*(.+\.json)\s*$", output, re.MULTILINE)
        if not match:
            raise RuntimeError("SploitScan did not produce a JSON export")
        export_path = Path(match.group(1).strip())
        if not export_path.is_absolute():
            export_path = Path(directory) / export_path
        try:
            records = json.loads(export_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise RuntimeError(f"Cannot read SploitScan export: {error}") from error

    indexed = {}
    for record in records if isinstance(records, list) else []:
        if not isinstance(record, dict):
            continue
        cve_data = record.get("CVE Data") or {}
        metadata = cve_data.get("cveMetadata") or {} if isinstance(cve_data, dict) else {}
        cve_id = metadata.get("cveId") if isinstance(metadata, dict) else None
        if cve_id:
            indexed[str(cve_id).upper()] = record
    return indexed

def sploitscan_values(record):
    """Return display values from one SploitScan JSON record."""
    record = record if isinstance(record, dict) else {}
    epss_record = record.get("EPSS Data") or {}
    epss_data = epss_record.get("data") or [] if isinstance(epss_record, dict) else []
    try:
        epss = f"{float(epss_data[0].get('epss', 0)):.1%}" if epss_data else "N/A"
    except (TypeError, ValueError):
        epss = "N/A"
    github = record.get("GitHub Data") or {}
    vulncheck = record.get("VulnCheck Data") or {}
    metasploit = record.get("Metasploit Data") or {}
    links = []
    for poc in github.get("pocs") or [] if isinstance(github, dict) else []:
        if isinstance(poc, dict):
            links.append(("GitHub", poc.get("html_url")))
    exploits = len(github.get("pocs") or []) if isinstance(github, dict) else 0
    exploits += sum(
        len(item.get("vulncheck_xdb") or [])
        for item in (vulncheck.get("data") or [] if isinstance(vulncheck, dict) else [])
        if isinstance(item, dict)
    )
    for item in vulncheck.get("data") or [] if isinstance(vulncheck, dict) else []:
        for exploit in item.get("vulncheck_xdb") or [] if isinstance(item, dict) else []:
            if isinstance(exploit, dict):
                url = str(exploit.get("clone_ssh_url") or "").replace("git@github.com:", "https://github.com/")
                links.append(("VulnCheck", url[:-4] if url.endswith(".git") else url))
    exploits += len(record.get("ExploitDB Data") or []) if isinstance(record.get("ExploitDB Data"), list) else 0
    for exploit in record.get("ExploitDB Data") or [] if isinstance(record.get("ExploitDB Data"), list) else []:
        if isinstance(exploit, dict) and str(exploit.get("id", "")).isdigit():
            links.append(("Exploit-DB", f'https://www.exploit-db.com/exploits/{exploit["id"]}'))
    exploits += len(metasploit.get("modules") or []) if isinstance(metasploit, dict) else 0
    for module in metasploit.get("modules") or [] if isinstance(metasploit, dict) else []:
        if isinstance(module, dict):
            links.append(("Metasploit", module.get("url")))
    nuclei = record.get("Nuclei Data") or {}
    exploits += int(isinstance(nuclei, dict) and bool(nuclei.get("file_path") or nuclei.get("raw_url")))
    if isinstance(nuclei, dict):
        links.append(("Nuclei", nuclei.get("raw_url")))
    links = list(dict.fromkeys(
        (source, str(url)) for source, url in links
        if re.match(r"https?://", str(url or ""), re.IGNORECASE)
    ))
    cisa = record.get("CISA Data") or {}
    cisa_status = cisa.get("cisa_status") if isinstance(cisa, dict) else None
    priority = record.get("Priority") or {}
    return {
        "epss": epss,
        "kev": cisa_status if cisa_status in ("Yes", "No") else "N/A",
        "priority": priority.get("Priority") or "N/A" if isinstance(priority, dict) else "N/A",
        "exploits": exploits,
        "links": links,
    }

def request_server_report(server_url, software, output_path, use_sploitscan=True):
    """Submit an inventory to CVEWatchdog Server and download its completed report."""
    server_url = server_url.rstrip("/")
    payload = {
        "hostname": platform.node(),
        "platform": PLATFORM,
        "software": [
            {"name": item.name, "version": item.version, "context": item.context}
            for item in software
        ],
        "options": {"sploitscan": use_sploitscan},
    }
    try:
        response = requests.post(f"{server_url}/api/v1/reports", json=payload, timeout=30)
        response.raise_for_status()
        job = response.json()
        job_id = job["id"]
    except (requests.RequestException, ValueError, KeyError, TypeError) as error:
        raise RuntimeError(f"Cannot submit inventory to CVEWatchdog Server: {error}") from error

    last_progress = None
    while True:
        try:
            response = requests.get(f"{server_url}/api/v1/reports/{job_id}", timeout=10)
            response.raise_for_status()
            job = response.json()
            if not isinstance(job, dict):
                raise ValueError("invalid status response")
        except (requests.RequestException, ValueError) as error:
            raise RuntimeError(f"Cannot read report status: {error}") from error
        if job.get("status") == "failed":
            raise RuntimeError(job.get("error") or "Server report failed")
        if job.get("status") == "completed":
            break
        progress = (job.get("processed", 0), job.get("total", 0), job.get("stage", "queued"))
        if progress != last_progress:
            print(f"  {progress[2]}: {progress[0]}/{progress[1]}")
            last_progress = progress
        time.sleep(2)

    try:
        response = requests.get(f"{server_url}/api/v1/reports/{job_id}/html", timeout=60)
        response.raise_for_status()
    except requests.RequestException as error:
        raise RuntimeError(f"Cannot download report: {error}") from error
    report_path = Path(output_path).expanduser()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_bytes(response.content)
    return report_path.resolve()

def write_html_report(path, software_with_cves, summary, sploitscan=None):
    """Write a standalone, escaped HTML vulnerability report."""
    sections = []
    software_choices = []
    report_cwes = set()
    for index, app in enumerate(software_with_cves):
        software_id = f"software-{index}"
        cve_count = len(app["cves"])
        cve_label = f'{cve_count} CVE{"s" if cve_count != 1 else ""}'
        software_choices.append(
            f'<label><input class="software-choice" type="checkbox" value="{software_id}" checked> '
            f'<span><strong>{html.escape(app["name"])}</strong> '
            f'<small>{html.escape(app["version"])}</small></span></label>'
            f'<span class="software-cve-count">{cve_label}</span>'
            f'<button type="button" data-only="{software_id}">Only</button>'
        )
        rows = []
        for cve in app["cves"]:
            cve_id = str(cve.get("cve_id", ""))
            severity = get_cvss_severity(cve.get("cvss_score"))
            score = cve.get("cvss_score")
            vulnerability_types = classify_vulnerability(str(cve.get("description", "")))
            cwes = sorted({
                str(value).upper() for value in (cve.get("cwes") or [])
                if re.fullmatch(r"CWE-\d+", str(value), re.IGNORECASE)
            }, key=lambda value: int(value[4:]))
            report_cwes.update(cwes)
            cwe_values = " ".join(cwes) or "unknown"
            cwe_badges = " ".join(
                f'<span class="cwe-chip" title="{html.escape(CWE_NAMES.get(cwe, "Unknown CWE"), quote=True)}">{cwe}</span>'
                for cwe in cwes
            ) or '<span class="cwe-chip">Unknown</span>'
            enrichment = sploitscan_values((sploitscan or {}).get(cve_id.upper()))
            exploit_links = "".join(
                f'<li><a href="{html.escape(url, quote=True)}" target="_blank" rel="noopener noreferrer">'
                f'{html.escape(source)} PoC</a></li>'
                for source, url in enrichment["links"]
            )
            exploit_cell = (
                f'<details><summary>{enrichment["exploits"]} exploit(s)</summary><ul>{exploit_links}</ul></details>'
                if exploit_links else str(enrichment["exploits"])
            )
            sploitscan_cells = (
                f'<td>{enrichment["epss"]}</td>'
                f'<td><span class="intel-chip">{enrichment["kev"]}</span></td>'
                f'<td><span class="intel-chip">{html.escape(str(enrichment["priority"]))}</span></td>'
                f'<td>{exploit_cell}</td>'
            ) if sploitscan is not None else ""
            rows.append(
                f'<tr class="row-{severity.lower()}" data-severity="{severity.lower()}" data-types="{" ".join(value for value, _ in vulnerability_types)}" data-cwes="{cwe_values}" data-poc="{str(enrichment["exploits"] > 0).lower()}">'
                f'<td><span class="cve-id">{html.escape(cve_id)}</span></td>'
                f'<td><span class="severity {severity.lower()}">{severity}</span></td>'
                f'<td><span class="type-chip">{html.escape(", ".join(label for _, label in vulnerability_types))}</span></td>'
                f'<td>{cwe_badges}</td>'
                f'<td>{html.escape(str(score if score is not None else "N/A"))}</td>'
                f'<td>{html.escape(str(cve.get("version", "")))}</td>'
                f'<td>{html.escape(str(cve.get("published", "")).split("T")[0])}</td>{sploitscan_cells}'
                f'<td>{html.escape(str(cve.get("description", "")))}</td></tr>'
            )
        sploitscan_headers = "<th>EPSS</th><th>CISA KEV</th><th>Priority</th><th>Exploits</th>" if sploitscan is not None else ""
        sections.append(
            f'<section class="report-section" data-software="{software_id}"><div class="section-heading"><div>'
            f'<h2>{html.escape(app["name"])} <small>{html.escape(app["version"])}</small></h2>'
            f'<p class="cpe">{html.escape(app["cpe"])}</p></div><span class="section-count">{cve_label}</span></div>'
            '<div class="table-wrap"><table><thead><tr><th>CVE</th><th>Severity</th><th>Type</th><th>CWE</th>'
            f'<th>CVSS</th><th>Affected version</th><th>Published</th>{sploitscan_headers}<th>Description</th>'
            f'</tr></thead><tbody>{"".join(rows)}</tbody></table></div></section>'
        )

    cards = "".join(
        f'<div class="metric-card {tone}"><span>{html.escape(label)}</span><strong>{value}</strong></div>'
        for label, value, tone in (
            ("Software scanned", summary["software_scanned"], "neutral"),
            ("Software resolved", summary["software_resolved"], "resolved"),
            ("Total CVEs", summary["total_cves"], "total"),
            ("Critical", summary["critical"], "critical"),
            ("High", summary["high"], "high"),
            ("Medium", summary["medium"], "medium"),
            ("Low", summary["low"], "low"),
            ("API errors", summary["api_errors"], "errors"),
        )
    )
    cwe_options = "".join(
        f'<option value="{cwe}">{cwe}: {html.escape(CWE_NAMES.get(cwe, "Unknown CWE"))}</option>'
        for cwe in sorted(report_cwes, key=lambda value: int(value[4:]))
    )
    poc_filter = (
        '<label>SploitScan PoC<select id="poc-filter"><option value="">All findings</option>'
        '<option value="true">With PoC</option><option value="false">Without PoC</option></select></label>'
        if sploitscan is not None else ""
    )
    filter_class = "filters has-poc-filter" if sploitscan is not None else "filters"
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CVEWatchdog report</title><style>
:root{{--bg:#0d1015;--panel:#15191f;--panel-2:#191e26;--text:#f1f5f9;--muted:#94a3b8;--border:#2b3440;--accent:#38bdf8;--accent-soft:#12303d;--critical:#fb7185;--high:#fb923c;--medium:#facc15;--low:#4ade80}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--text);font:14px Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;line-height:1.5}}
main{{max-width:1480px;margin:auto;padding:36px 28px 64px}} h1,h2,p{{margin-top:0}} button,input,select{{font:inherit}}
.hero{{display:flex;justify-content:space-between;align-items:center;gap:24px;margin-bottom:24px;padding:24px 26px;border:1px solid var(--border);border-radius:10px;background:var(--panel)}}
.brand{{display:flex;align-items:center;gap:18px}} .mark{{display:grid;place-items:center;width:54px;height:54px;border-radius:8px;background:#2563eb;font-size:18px;font-weight:900;letter-spacing:-1px}}
.eyebrow{{margin-bottom:5px;color:#67e8f9;font-size:11px;font-weight:800;letter-spacing:.16em;text-transform:uppercase}} h1{{margin-bottom:3px;font-size:30px;line-height:1.1;letter-spacing:-.03em}} .subtitle{{margin-bottom:0;color:#b5c2d4}}
.risk-card{{min-width:190px;padding:14px 18px;border:1px solid #38506b;border-radius:14px;background:rgba(5,11,22,.45);text-align:right}} .risk-card span{{display:block;margin-bottom:5px;color:var(--muted);font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.1em}} .risk-card strong{{font-size:16px}}
.panel,.report-section,.empty-state{{margin:18px 0;border:1px solid var(--border);border-radius:10px;background:var(--panel)}}
.panel{{padding:20px}} .panel-title,.section-heading{{display:flex;align-items:center;justify-content:space-between;gap:16px}} .panel-title h2,.section-heading h2{{margin:0;font-size:18px;letter-spacing:-.01em}} .panel-title p{{margin:3px 0 0;color:var(--muted)}}
.actions{{display:flex;gap:8px}} button{{padding:7px 12px;border:1px solid #34445e;border-radius:6px;background:#1b222c;color:#dce5f2;cursor:pointer;transition:transform .12s ease,background .12s ease,border-color .12s ease}} button:hover{{border-color:#4c6b8d;background:#232d39;transform:translateY(-1px)}} button:active{{transform:scale(.98)}}
.software-list{{display:grid;grid-template-columns:minmax(180px,1fr) auto auto;column-gap:14px;align-items:center;max-height:290px;overflow:auto;margin-top:16px;padding-right:14px;border-top:1px solid var(--border);scrollbar-width:thin;scrollbar-color:#4b5563 #11151b}} .software-list::-webkit-scrollbar{{width:10px}} .software-list::-webkit-scrollbar-track{{background:#11151b}} .software-list::-webkit-scrollbar-thumb{{border:2px solid #11151b;border-radius:8px;background:#4b5563}} .software-list::-webkit-scrollbar-thumb:hover{{background:#64748b}} .software-list>*{{padding:10px 8px;border-bottom:1px solid rgba(38,51,74,.7)}} .software-list label{{display:flex;gap:10px;align-items:center;min-width:0}} .software-list input{{accent-color:var(--accent)}} .software-list small{{color:var(--muted)}} .software-cve-count{{color:#b8c6d8;font-variant-numeric:tabular-nums}}
.cards{{display:grid;grid-template-columns:repeat(4,minmax(140px,1fr));gap:12px;margin:18px 0}} .metric-card{{position:relative;overflow:hidden;padding:17px 18px;border:1px solid var(--border);border-radius:8px;background:var(--panel)}} .metric-card::before{{content:"";position:absolute;inset:0 auto 0 0;width:3px;background:#64748b}} .metric-card span{{display:block;color:var(--muted);font-size:12px;font-weight:650}} .metric-card strong{{display:block;margin-top:4px;font-size:26px;line-height:1.2;font-variant-numeric:tabular-nums}} .metric-card.resolved::before,.metric-card.low::before{{background:var(--low)}} .metric-card.total::before{{background:var(--accent)}} .metric-card.critical::before{{background:var(--critical)}} .metric-card.high::before{{background:var(--high)}} .metric-card.medium::before{{background:var(--medium)}} .metric-card.errors::before{{background:#a78bfa}}
.filter-panel{{padding:17px 20px}} .filter-head{{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}} .filter-head strong{{font-size:15px}} #visible-count,.section-count{{padding:5px 10px;border:1px solid #28536a;border-radius:999px;background:var(--accent-soft);color:#a5f3fc;font-size:12px;font-weight:750}}
.filters{{display:grid;grid-template-columns:minmax(240px,1.4fr) repeat(3,minmax(170px,1fr));gap:12px}} .filters.has-poc-filter{{grid-template-columns:minmax(240px,1.4fr) repeat(4,minmax(150px,1fr))}} .filters label{{display:grid;gap:6px;color:var(--muted);font-size:12px;font-weight:650}} .filters input,.filters select{{width:100%;padding:10px 12px;border:1px solid #34445e;border-radius:9px;outline:none;background:#0c1422;color:var(--text)}} .filters input:focus,.filters select:focus{{border-color:var(--accent);box-shadow:0 0 0 3px rgba(34,211,238,.12)}}
.report-section{{overflow:hidden}} .section-heading{{padding:18px 20px}} .section-heading h2 small{{margin-left:6px;color:var(--muted);font-weight:500}} .cpe{{margin:4px 0 0;color:#8291a7;font:12px ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere}}
.table-wrap{{overflow:auto}} table{{width:100%;border-collapse:collapse}} th{{padding:11px 13px;border-top:1px solid var(--border);border-bottom:1px solid var(--border);background:#0d1625;color:#90a0b6;font-size:11px;letter-spacing:.06em;text-align:left;text-transform:uppercase;white-space:nowrap}} td{{padding:12px 13px;border-bottom:1px solid rgba(38,51,74,.65);vertical-align:top}} tbody tr:last-child td{{border-bottom:0}} tbody tr:hover{{background:rgba(34,211,238,.035)}} .cve-id{{font-weight:750;color:#dbeafe;white-space:nowrap}}
.severity,.type-chip,.cwe-chip,.intel-chip{{display:inline-block;padding:3px 8px;border-radius:999px;font-size:11px;font-weight:800;white-space:nowrap}} .severity.critical{{background:rgba(251,113,133,.13);color:var(--critical)}} .severity.high{{background:rgba(251,146,60,.13);color:var(--high)}} .severity.medium{{background:rgba(250,204,21,.13);color:var(--medium)}} .severity.low{{background:rgba(74,222,128,.13);color:var(--low)}} .severity.unknown{{background:#263246;color:#bac4d2}} .type-chip{{background:#202b40;color:#cbd5e1;font-weight:650}} .cwe-chip{{background:rgba(34,211,238,.1);color:#a5f3fc;font-weight:650}} .intel-chip{{background:rgba(167,139,250,.12);color:#ddd6fe}}
details summary{{color:#a5f3fc;cursor:pointer;white-space:nowrap}} details ul{{min-width:130px;margin:7px 0 0;padding-left:18px}} details a{{color:#93c5fd;text-decoration:none}} details a:hover{{text-decoration:underline}}
.empty-state{{padding:36px;text-align:center;color:var(--muted)}} footer{{padding-top:24px;color:#66758a;text-align:center;font-size:12px}}
@media(max-width:900px){{main{{padding:20px 14px 40px}} .hero{{align-items:flex-start;padding:22px;flex-direction:column}} .risk-card{{width:100%;text-align:left}} .cards{{grid-template-columns:repeat(2,1fr)}} .filters,.filters.has-poc-filter{{grid-template-columns:1fr}}}}
@media(max-width:560px){{.mark{{display:none}} .panel-title{{align-items:flex-start;flex-direction:column}} .software-list{{grid-template-columns:minmax(130px,1fr) auto}} .software-cve-count{{display:none}} .cards{{grid-template-columns:1fr 1fr}} .metric-card{{padding:14px}}}}
</style></head><body><main><header class="hero"><div class="brand"><div class="mark">CV</div><div><p class="eyebrow">Local vulnerability assessment</p><h1>CVEWatchdog</h1><p class="subtitle">Version-confirmed vulnerability report</p></div></div><div class="risk-card"><span>Overall risk</span><strong>{html.escape(summary["risk_level"])}</strong></div></header>
<section class="panel software-summary"><div class="panel-title"><div><h2>Vulnerable software</h2><p>Select the applications to include in the report.</p></div><div class="actions"><button type="button" id="software-all">Select all</button><button type="button" id="software-none">Select none</button></div></div><div class="software-list">{"".join(software_choices) or "No vulnerable software"}</div></section>
<div class="cards">{cards}</div>
<section class="panel filter-panel"><div class="filter-head"><strong>Filter findings</strong><span id="visible-count"></span></div><div class="{filter_class}"><label>Search<input id="report-search" type="search" placeholder="Software, CPE, CVE, CWE, description"></label>
<label>Severity<select id="severity-filter"><option value="">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="unknown">Unknown</option></select></label>
<label>Vulnerability type<select id="type-filter"><option value="">All types</option><option value="lpe">LPE</option><option value="rce">RCE</option><option value="privilege-escalation">Privilege escalation</option><option value="dos">DoS</option><option value="information-disclosure">Information disclosure</option><option value="authentication-bypass">Authentication bypass</option><option value="xss">XSS</option><option value="sql-injection">SQL injection</option><option value="path-traversal">Path traversal</option><option value="other">Other</option></select></label>
<label>CWE<select id="cwe-filter"><option value="">All CWEs</option>{cwe_options}<option value="unknown">Unknown</option></select></label>
{poc_filter}</div></section>{"".join(sections) or '<section class="empty-state">No version-confirmed vulnerabilities found</section>'}<footer>Generated locally by CVEWatchdog</footer>
</main><script>
const search=document.getElementById('report-search'), severity=document.getElementById('severity-filter'), type=document.getElementById('type-filter'), cwe=document.getElementById('cwe-filter'), poc=document.getElementById('poc-filter'), count=document.getElementById('visible-count'), software=[...document.querySelectorAll('.software-choice')];
const reportSections=[...document.querySelectorAll('.report-section')].map(section=>{{let context=(section.querySelector('h2').textContent+' '+section.querySelector('.cpe').textContent).toLowerCase(),rows=[...section.querySelectorAll('tbody tr')];rows.forEach(row=>row.filterText=context+' '+row.textContent.toLowerCase());return{{section,rows}};}});
function filterReport(){{let visible=0,query=search.value.trim().toLowerCase(),selected=new Set(software.filter(choice=>choice.checked).map(choice=>choice.value));reportSections.forEach(item=>{{let sectionRows=0;item.rows.forEach(row=>{{let show=selected.has(item.section.dataset.software)&&(!query||row.filterText.includes(query))&&(!severity.value||row.dataset.severity===severity.value)&&(!type.value||row.dataset.types.split(' ').includes(type.value))&&(!cwe.value||row.dataset.cwes.split(' ').includes(cwe.value))&&(!poc||!poc.value||row.dataset.poc===poc.value);row.hidden=!show;if(show){{visible++;sectionRows++;}}}});item.section.hidden=sectionRows===0;}});count.textContent=visible+' CVE'+(visible===1?'':'s')+' shown';}}
search.addEventListener('input',filterReport);severity.addEventListener('change',filterReport);type.addEventListener('change',filterReport);cwe.addEventListener('change',filterReport);if(poc)poc.addEventListener('change',filterReport);software.forEach(choice=>choice.addEventListener('change',filterReport));
document.getElementById('software-all').addEventListener('click',()=>{{software.forEach(choice=>choice.checked=true);filterReport();}});document.getElementById('software-none').addEventListener('click',()=>{{software.forEach(choice=>choice.checked=false);filterReport();}});document.querySelectorAll('[data-only]').forEach(button=>button.addEventListener('click',()=>{{software.forEach(choice=>choice.checked=choice.value===button.dataset.only);filterReport();}}));filterReport();
</script></body></html>"""
    document = document.replace("—", "-").replace("–", "-")
    report_path = Path(path).expanduser()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(document, encoding="utf-8")
    return report_path.resolve()

def main():
    parser = argparse.ArgumentParser(description='CVEWatchdog - Linux Vulnerability Scanner')
    parser.add_argument(
        'api_url',
        nargs='?',
        default='http://localhost:8001',
        help='CVE API URL (default: http://localhost:8001)',
    )
    parser.add_argument('--wildcards', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--debug', action='store_true', help='Enable debug output for matching')
    parser.add_argument('--html-report', metavar='PATH', help='Write a standalone HTML report')
    parser.add_argument('--sploitscan', action='store_true', help='Enrich the HTML report with SploitScan intelligence')
    parser.add_argument('--server-url', help='Send the inventory to CVEWatchdog Server instead of FastCVE-API')
    parser.add_argument('--no-sploitscan', action='store_true', help='Disable SploitScan in server mode')
    
    args = parser.parse_args()
    if args.sploitscan and not args.html_report:
        parser.error('--sploitscan requires --html-report')
    
    print(f"\n{Colors.CYAN}{'═' * 45}")
    print("                CVEWatchdog                ")
    print(f"{'═' * 45}{Colors.RESET}\n")

    if args.server_url:
        software_list, _ = get_installed_software()
        destination = args.html_report or "cvewatchdog-report.html"
        print(f"\n{Colors.CYAN}📡 Sending inventory to CVEWatchdog Server...{Colors.RESET}")
        try:
            report_path = request_server_report(
                args.server_url, software_list, destination, not args.no_sploitscan
            )
        except (RuntimeError, OSError) as error:
            print(f"{Colors.RED}❌ Server report error: {error}{Colors.RESET}")
            sys.exit(1)
        print(f"{Colors.GREEN}✅ HTML report downloaded to {report_path}{Colors.RESET}")
        return
    
    # Check API connectivity
    print(f"{Colors.CYAN}🌐 Checking API connectivity...{Colors.RESET}")
    try:
        response = requests.get(f"{args.api_url.rstrip('/')}/health", timeout=5)
        response.raise_for_status()
        health = response.json()
        print(f"{Colors.GREEN}✅ API connected - {health.get('cves_indexed', 0)} CVEs indexed{Colors.RESET}\n")
    except requests.RequestException as error:
        print(f"{Colors.RED}❌ Cannot connect to API at {args.api_url}: {error}{Colors.RESET}")
        sys.exit(1)
    except ValueError:
        print(f"{Colors.RED}❌ {args.api_url} did not return a FastCVE-API health response{Colors.RESET}")
        sys.exit(1)
    
    # Get installed software
    software_list, ignored_count = get_installed_software()
    
    print(f"\n{Colors.CYAN}🔍 Searching for vulnerabilities...{Colors.RESET}\n")
    
    software_with_cves = []
    all_cves = []
    api_matches = 0
    api_errors = 0
    
    for app in software_list:
        try:
            cve_result = resolve_software(args.api_url, app.name, app.version, app.context)
        except (requests.RequestException, ValueError) as error:
            api_errors += 1
            print(f"{Colors.RED}✗ {app.name} ({app.version}) - API error: {error}{Colors.RESET}")
            continue

        matched_cpe = cve_result.get('matched_cpe')
        cves = cve_result.get('results', [])
        if matched_cpe:
            api_matches += 1
            if args.debug:
                print(
                    f"{Colors.GRAY}↳ {app.name}: {matched_cpe['cpe']} "
                    f"(confidence {matched_cpe['score']:.2f}){Colors.RESET}"
                )
        
        if cves:
            print(f"{Colors.YELLOW}⚠️  {app.name} ({app.version}) - {len(cves)} CVE(s) detected{Colors.RESET}")
            software_with_cves.append({
                'name': app.name,
                'version': app.version,
                'cpe': matched_cpe['cpe'],
                'cves': cves
            })
            all_cves.extend(cves)
        else:
            if args.debug and not matched_cpe:
                print(f"{Colors.GRAY}? {app.name} ({app.version}) - Software not resolved{Colors.RESET}")
            elif args.debug:
                print(f"{Colors.GREEN}✓ {app.name} ({app.version}) - No CVEs detected{Colors.RESET}")
    
    # Print vulnerability report
    print(f"\n{'═' * 45}")
    print("            VULNERABILITY REPORT")
    print(f"{'═' * 45}\n")
    
    if not software_with_cves:
        print(f"{Colors.GREEN}✅ No vulnerabilities detected!{Colors.RESET}")
    else:
        for app in software_with_cves:
            print(f"\n{Colors.MAGENTA}📌 {app['name']} - Version: {app['version']}{Colors.RESET}")
            print(f"{Colors.GRAY}   CPE: {app['cpe']}{Colors.RESET}")
            format_cve_table(app['cves'])
    
    # Print summary
    print(f"\n{'═' * 45}")
    print("               SUMMARY")
    print(f"{'═' * 45}\n")
    
    total_cves = len(all_cves)
    critical_count = sum(1 for cve in all_cves if get_cvss_severity(cve.get('cvss_score')) == "Critical")
    high_count = sum(1 for cve in all_cves if get_cvss_severity(cve.get('cvss_score')) == "High")
    medium_count = sum(1 for cve in all_cves if get_cvss_severity(cve.get('cvss_score')) == "Medium")
    low_count = sum(1 for cve in all_cves if get_cvss_severity(cve.get('cvss_score')) == "Low")
    unknown_count = sum(1 for cve in all_cves if get_cvss_severity(cve.get('cvss_score')) == "Unknown")
    
    print(f"Software scanned        : {len(software_list)}")
    print(f"Software ignored        : {ignored_count}")
    print(f"Software resolved       : {api_matches}")
    print(f"API errors              : {api_errors}")
    print()
    print(f"{Colors.CYAN}Total CVEs found        : {total_cves}{Colors.RESET}")
    print(f"{Colors.BLACK}Critical vulnerabilities: {critical_count}{Colors.RESET}")
    print(f"{Colors.RED}High vulnerabilities    : {high_count}{Colors.RESET}")
    print(f"{Colors.YELLOW}Medium vulnerabilities  : {medium_count}{Colors.RESET}")
    print(f"{Colors.GREEN}Low vulnerabilities     : {low_count}{Colors.RESET}")
    
    if unknown_count > 0:
        print(f"{Colors.GRAY}Unknown vulnerabilities : {unknown_count}{Colors.RESET}")
    
    print()
    
    # Risk assessment
    risk_level = "🟢 LOW RISK"
    risk_color = Colors.GREEN
    
    if critical_count > 0:
        risk_level = "⚫️ CRITICAL RISK"
        risk_color = Colors.BLACK
    elif high_count > 3:
        risk_level = "🔴 HIGH RISK"
        risk_color = Colors.RED
    elif high_count > 0:
        risk_level = "🟠 MEDIUM RISK"
        risk_color = Colors.YELLOW
    
    print(f"Overall Risk Assessment : {risk_color}{risk_level}{Colors.RESET}")
    print()

    if args.html_report:
        sploitscan_results = None
        if args.sploitscan:
            print(f"{Colors.CYAN}🧨 Enriching {len(set(cve.get('cve_id') for cve in all_cves))} CVEs with SploitScan...{Colors.RESET}")
            try:
                sploitscan_results = run_sploitscan(all_cves)
            except RuntimeError as error:
                print(f"{Colors.RED}❌ SploitScan error: {error}{Colors.RESET}")
                sys.exit(1)
        summary = {
            "software_scanned": len(software_list),
            "software_resolved": api_matches,
            "api_errors": api_errors,
            "total_cves": total_cves,
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "risk_level": risk_level,
        }
        try:
            report_path = write_html_report(args.html_report, software_with_cves, summary, sploitscan_results)
        except OSError as error:
            print(f"{Colors.RED}❌ Cannot write HTML report: {error}{Colors.RESET}")
            sys.exit(1)
        print(f"{Colors.GREEN}✅ HTML report written to {report_path}{Colors.RESET}")

if __name__ == "__main__":
    main()
