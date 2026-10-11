import argparse
import html
import os
import re
import subprocess
import sys
from pathlib import Path
import requests

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

def resolve_software(api_url, software_name, version, context=""):
    """Resolve software to a CPE and applicable CVEs through FastCVE-API."""
    response = requests.post(
        f"{api_url.rstrip('/')}/api/resolve",
        json={
            "software": software_name,
            "version": version,
            "context": context,
            "platform": PLATFORM,
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
    if privilege and local:
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

def write_html_report(path, software_with_cves, summary):
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
            severity = get_cvss_severity(cve.get("cvss_score"))
            score = cve.get("cvss_score")
            vulnerability_types = classify_vulnerability(str(cve.get("description", "")))
            cwes = sorted({
                str(value).upper() for value in (cve.get("cwes") or [])
                if re.fullmatch(r"CWE-\d+", str(value), re.IGNORECASE)
            }, key=lambda value: int(value[4:]))
            report_cwes.update(cwes)
            cwe_values = " ".join(cwes) or "unknown"
            cwe_label = ", ".join(cwes) or "Unknown"
            rows.append(
                f'<tr class="row-{severity.lower()}" data-severity="{severity.lower()}" data-types="{" ".join(value for value, _ in vulnerability_types)}" data-cwes="{cwe_values}">'
                f'<td><span class="cve-id">{html.escape(str(cve.get("cve_id", "")))}</span></td>'
                f'<td><span class="severity {severity.lower()}">{severity}</span></td>'
                f'<td><span class="type-chip">{html.escape(", ".join(label for _, label in vulnerability_types))}</span></td>'
                f'<td><span class="cwe-chip">{cwe_label}</span></td>'
                f'<td>{html.escape(str(score if score is not None else "N/A"))}</td>'
                f'<td>{html.escape(str(cve.get("version", "")))}</td>'
                f'<td>{html.escape(str(cve.get("published", "")).split("T")[0])}</td>'
                f'<td>{html.escape(str(cve.get("description", "")))}</td></tr>'
            )
        sections.append(
            f'<section class="report-section" data-software="{software_id}"><div class="section-heading"><div>'
            f'<h2>{html.escape(app["name"])} <small>{html.escape(app["version"])}</small></h2>'
            f'<p class="cpe">{html.escape(app["cpe"])}</p></div><span class="section-count">{cve_label}</span></div>'
            '<div class="table-wrap"><table><thead><tr><th>CVE</th><th>Severity</th><th>Type</th><th>CWE</th>'
            '<th>CVSS</th><th>Affected version</th><th>Published</th><th>Description</th>'
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
        f'<option value="{cwe}">{cwe}</option>'
        for cwe in sorted(report_cwes, key=lambda value: int(value[4:]))
    )
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CVEWatchdog report</title><style>
:root{{--bg:#070b14;--panel:#101827;--panel-2:#151f31;--text:#f5f7fb;--muted:#94a3b8;--border:#26334a;--accent:#22d3ee;--accent-soft:#123644;--critical:#fb7185;--high:#fb923c;--medium:#facc15;--low:#4ade80}}
*{{box-sizing:border-box}} html{{scroll-behavior:smooth}} body{{margin:0;background:radial-gradient(circle at 15% 0,#11233b 0,transparent 32%),var(--bg);color:var(--text);font:14px Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;line-height:1.5}}
main{{max-width:1480px;margin:auto;padding:36px 28px 64px}} h1,h2,p{{margin-top:0}} button,input,select{{font:inherit}}
.hero{{display:flex;justify-content:space-between;align-items:center;gap:24px;margin-bottom:24px;padding:28px 30px;border:1px solid #28405c;border-radius:20px;background:linear-gradient(125deg,rgba(20,49,72,.96),rgba(14,24,40,.96));box-shadow:0 24px 70px rgba(0,0,0,.25)}}
.brand{{display:flex;align-items:center;gap:18px}} .mark{{display:grid;place-items:center;width:58px;height:58px;border:1px solid #3b7187;border-radius:16px;background:linear-gradient(145deg,#22d3ee,#2563eb);font-size:18px;font-weight:900;letter-spacing:-1px;box-shadow:0 10px 30px rgba(34,211,238,.18)}}
.eyebrow{{margin-bottom:5px;color:#67e8f9;font-size:11px;font-weight:800;letter-spacing:.16em;text-transform:uppercase}} h1{{margin-bottom:3px;font-size:30px;line-height:1.1;letter-spacing:-.03em}} .subtitle{{margin-bottom:0;color:#b5c2d4}}
.risk-card{{min-width:190px;padding:14px 18px;border:1px solid #38506b;border-radius:14px;background:rgba(5,11,22,.45);text-align:right}} .risk-card span{{display:block;margin-bottom:5px;color:var(--muted);font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.1em}} .risk-card strong{{font-size:16px}}
.panel,.report-section,.empty-state{{margin:18px 0;border:1px solid var(--border);border-radius:16px;background:linear-gradient(180deg,rgba(21,31,49,.98),rgba(15,23,38,.98));box-shadow:0 10px 35px rgba(0,0,0,.13)}}
.panel{{padding:20px}} .panel-title,.section-heading{{display:flex;align-items:center;justify-content:space-between;gap:16px}} .panel-title h2,.section-heading h2{{margin:0;font-size:18px;letter-spacing:-.01em}} .panel-title p{{margin:3px 0 0;color:var(--muted)}}
.actions{{display:flex;gap:8px}} button{{padding:7px 12px;border:1px solid #34445e;border-radius:8px;background:#111b2b;color:#dce5f2;cursor:pointer;transition:.15s ease}} button:hover{{border-color:#4c6b8d;background:#19263a}}
.software-list{{display:grid;grid-template-columns:minmax(180px,1fr) auto auto;column-gap:14px;align-items:center;max-height:290px;overflow:auto;margin-top:16px;padding-right:14px;border-top:1px solid var(--border);scrollbar-width:thin;scrollbar-color:#46617e #0b1422}} .software-list::-webkit-scrollbar{{width:10px}} .software-list::-webkit-scrollbar-track{{border-radius:999px;background:#0b1422}} .software-list::-webkit-scrollbar-thumb{{border:2px solid #0b1422;border-radius:999px;background:linear-gradient(#4b6b8d,#304761)}} .software-list::-webkit-scrollbar-thumb:hover{{background:#587a9e}} .software-list>*{{padding:10px 8px;border-bottom:1px solid rgba(38,51,74,.7)}} .software-list label{{display:flex;gap:10px;align-items:center;min-width:0}} .software-list input{{accent-color:var(--accent)}} .software-list small{{color:var(--muted)}} .software-cve-count{{color:#b8c6d8;font-variant-numeric:tabular-nums}}
.cards{{display:grid;grid-template-columns:repeat(4,minmax(140px,1fr));gap:12px;margin:18px 0}} .metric-card{{position:relative;overflow:hidden;padding:17px 18px;border:1px solid var(--border);border-radius:14px;background:var(--panel);box-shadow:0 8px 24px rgba(0,0,0,.1)}} .metric-card::before{{content:"";position:absolute;inset:0 auto 0 0;width:3px;background:#64748b}} .metric-card span{{display:block;color:var(--muted);font-size:12px;font-weight:650}} .metric-card strong{{display:block;margin-top:4px;font-size:26px;line-height:1.2;font-variant-numeric:tabular-nums}} .metric-card.resolved::before,.metric-card.low::before{{background:var(--low)}} .metric-card.total::before{{background:var(--accent)}} .metric-card.critical::before{{background:var(--critical)}} .metric-card.high::before{{background:var(--high)}} .metric-card.medium::before{{background:var(--medium)}} .metric-card.errors::before{{background:#a78bfa}}
.filter-panel{{position:sticky;top:12px;z-index:5;padding:17px 20px;box-shadow:0 14px 40px rgba(0,0,0,.3)}} .filter-head{{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}} .filter-head strong{{font-size:15px}} #visible-count,.section-count{{padding:5px 10px;border:1px solid #28536a;border-radius:999px;background:var(--accent-soft);color:#a5f3fc;font-size:12px;font-weight:750}}
.filters{{display:grid;grid-template-columns:minmax(240px,1.4fr) repeat(3,minmax(170px,1fr));gap:12px}} .filters label{{display:grid;gap:6px;color:var(--muted);font-size:12px;font-weight:650}} .filters input,.filters select{{width:100%;padding:10px 12px;border:1px solid #34445e;border-radius:9px;outline:none;background:#0c1422;color:var(--text)}} .filters input:focus,.filters select:focus{{border-color:var(--accent);box-shadow:0 0 0 3px rgba(34,211,238,.12)}}
.report-section{{overflow:hidden}} .section-heading{{padding:18px 20px}} .section-heading h2 small{{margin-left:6px;color:var(--muted);font-weight:500}} .cpe{{margin:4px 0 0;color:#8291a7;font:12px ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere}}
.table-wrap{{overflow:auto}} table{{width:100%;border-collapse:collapse}} th{{padding:11px 13px;border-top:1px solid var(--border);border-bottom:1px solid var(--border);background:#0d1625;color:#90a0b6;font-size:11px;letter-spacing:.06em;text-align:left;text-transform:uppercase;white-space:nowrap}} td{{padding:12px 13px;border-bottom:1px solid rgba(38,51,74,.65);vertical-align:top}} tbody tr:last-child td{{border-bottom:0}} tbody tr:hover{{background:rgba(34,211,238,.035)}} .cve-id{{font-weight:750;color:#dbeafe;white-space:nowrap}}
.severity,.type-chip,.cwe-chip{{display:inline-block;padding:3px 8px;border-radius:999px;font-size:11px;font-weight:800;white-space:nowrap}} .severity.critical{{background:rgba(251,113,133,.13);color:var(--critical)}} .severity.high{{background:rgba(251,146,60,.13);color:var(--high)}} .severity.medium{{background:rgba(250,204,21,.13);color:var(--medium)}} .severity.low{{background:rgba(74,222,128,.13);color:var(--low)}} .severity.unknown{{background:#263246;color:#bac4d2}} .type-chip{{background:#202b40;color:#cbd5e1;font-weight:650}} .cwe-chip{{background:rgba(34,211,238,.1);color:#a5f3fc;font-weight:650}}
.empty-state{{padding:36px;text-align:center;color:var(--muted)}} footer{{padding-top:24px;color:#66758a;text-align:center;font-size:12px}}
@media(max-width:900px){{main{{padding:20px 14px 40px}} .hero{{align-items:flex-start;padding:22px;flex-direction:column}} .risk-card{{width:100%;text-align:left}} .cards{{grid-template-columns:repeat(2,1fr)}} .filter-panel{{position:static}} .filters{{grid-template-columns:1fr}}}}
@media(max-width:560px){{.mark{{display:none}} .panel-title{{align-items:flex-start;flex-direction:column}} .software-list{{grid-template-columns:minmax(130px,1fr) auto}} .software-cve-count{{display:none}} .cards{{grid-template-columns:1fr 1fr}} .metric-card{{padding:14px}}}}
</style></head><body><main><header class="hero"><div class="brand"><div class="mark">CV</div><div><p class="eyebrow">Local vulnerability assessment</p><h1>CVEWatchdog</h1><p class="subtitle">Version-confirmed vulnerability report</p></div></div><div class="risk-card"><span>Overall risk</span><strong>{html.escape(summary["risk_level"])}</strong></div></header>
<section class="panel software-summary"><div class="panel-title"><div><h2>Vulnerable software</h2><p>Select the applications to include in the report.</p></div><div class="actions"><button type="button" id="software-all">Select all</button><button type="button" id="software-none">Select none</button></div></div><div class="software-list">{"".join(software_choices) or "No vulnerable software"}</div></section>
<div class="cards">{cards}</div>
<section class="panel filter-panel"><div class="filter-head"><strong>Filter findings</strong><span id="visible-count"></span></div><div class="filters"><label>Search<input id="report-search" type="search" placeholder="Software, CPE, CVE, CWE, description"></label>
<label>Severity<select id="severity-filter"><option value="">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="unknown">Unknown</option></select></label>
<label>Vulnerability type<select id="type-filter"><option value="">All types</option><option value="lpe">LPE</option><option value="rce">RCE</option><option value="privilege-escalation">Privilege escalation</option><option value="dos">DoS</option><option value="information-disclosure">Information disclosure</option><option value="authentication-bypass">Authentication bypass</option><option value="xss">XSS</option><option value="sql-injection">SQL injection</option><option value="path-traversal">Path traversal</option><option value="other">Other</option></select></label>
<label>CWE<select id="cwe-filter"><option value="">All CWEs</option>{cwe_options}<option value="unknown">Unknown</option></select></label>
 </div></section>{"".join(sections) or '<section class="empty-state">No version-confirmed vulnerabilities found</section>'}<footer>Generated locally by CVEWatchdog</footer>
</main><script>
const search=document.getElementById('report-search'), severity=document.getElementById('severity-filter'), type=document.getElementById('type-filter'), cwe=document.getElementById('cwe-filter'), count=document.getElementById('visible-count'), software=[...document.querySelectorAll('.software-choice')];
function filterReport(){{let visible=0,query=search.value.trim().toLowerCase(),selected=new Set(software.filter(choice=>choice.checked).map(choice=>choice.value));document.querySelectorAll('.report-section').forEach(section=>{{let sectionRows=0,context=(section.querySelector('h2').textContent+' '+section.querySelector('.cpe').textContent).toLowerCase();section.querySelectorAll('tbody tr').forEach(row=>{{let show=selected.has(section.dataset.software)&&(!query||(context+' '+row.textContent).toLowerCase().includes(query))&&(!severity.value||row.dataset.severity===severity.value)&&(!type.value||row.dataset.types.split(' ').includes(type.value))&&(!cwe.value||row.dataset.cwes.split(' ').includes(cwe.value));row.hidden=!show;if(show){{visible++;sectionRows++;}}}});section.hidden=sectionRows===0;}});count.textContent=visible+' CVE'+(visible===1?'':'s')+' shown';}}
search.addEventListener('input',filterReport);severity.addEventListener('change',filterReport);type.addEventListener('change',filterReport);cwe.addEventListener('change',filterReport);software.forEach(choice=>choice.addEventListener('change',filterReport));
document.getElementById('software-all').addEventListener('click',()=>{{software.forEach(choice=>choice.checked=true);filterReport();}});document.getElementById('software-none').addEventListener('click',()=>{{software.forEach(choice=>choice.checked=false);filterReport();}});document.querySelectorAll('[data-only]').forEach(button=>button.addEventListener('click',()=>{{software.forEach(choice=>choice.checked=choice.value===button.dataset.only);filterReport();}}));filterReport();
</script></body></html>"""
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
    
    args = parser.parse_args()
    
    print(f"\n{Colors.CYAN}{'═' * 45}")
    print("                CVEWatchdog                ")
    print(f"{'═' * 45}{Colors.RESET}\n")
    
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
            report_path = write_html_report(args.html_report, software_with_cves, summary)
        except OSError as error:
            print(f"{Colors.RED}❌ Cannot write HTML report: {error}{Colors.RESET}")
            sys.exit(1)
        print(f"{Colors.GREEN}✅ HTML report written to {report_path}{Colors.RESET}")

if __name__ == "__main__":
    main()
