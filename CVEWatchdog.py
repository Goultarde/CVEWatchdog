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
    if any(term in text for term in ("remote code execution", "remotely execute arbitrary code", "execute arbitrary code remotely")):
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
    for index, app in enumerate(software_with_cves):
        software_id = f"software-{index}"
        software_choices.append(
            f'<label><input class="software-choice" type="checkbox" value="{software_id}" checked> '
            f'<span>{html.escape(app["name"])} {html.escape(app["version"])} '
            f'({len(app["cves"])} CVEs)</span></label>'
            f'<button type="button" data-only="{software_id}">Only</button>'
        )
        rows = []
        for cve in app["cves"]:
            severity = get_cvss_severity(cve.get("cvss_score"))
            score = cve.get("cvss_score")
            vulnerability_types = classify_vulnerability(str(cve.get("description", "")))
            rows.append(
                f'<tr data-severity="{severity.lower()}" data-types="{" ".join(value for value, _ in vulnerability_types)}">'
                f'<td>{html.escape(str(cve.get("cve_id", "")))}</td>'
                f'<td><span class="severity {severity.lower()}">{severity}</span></td>'
                f'<td>{html.escape(", ".join(label for _, label in vulnerability_types))}</td>'
                f'<td>{html.escape(str(score if score is not None else "N/A"))}</td>'
                f'<td>{html.escape(str(cve.get("version", "")))}</td>'
                f'<td>{html.escape(str(cve.get("published", "")).split("T")[0])}</td>'
                f'<td>{html.escape(str(cve.get("description", "")))}</td></tr>'
            )
        sections.append(
            f'<section class="report-section" data-software="{software_id}"><h2>{html.escape(app["name"])} '
            f'<small>{html.escape(app["version"])}</small></h2>'
            f'<p class="cpe">{html.escape(app["cpe"])}</p>'
            '<div class="table-wrap"><table><thead><tr><th>CVE</th><th>Severity</th><th>Type</th>'
            '<th>CVSS</th><th>Affected version</th><th>Published</th><th>Description</th>'
            f'</tr></thead><tbody>{"".join(rows)}</tbody></table></div></section>'
        )

    cards = "".join(
        f'<div class="card"><strong>{html.escape(label)}</strong><span>{value}</span></div>'
        for label, value in (
            ("Software scanned", summary["software_scanned"]),
            ("Software resolved", summary["software_resolved"]),
            ("Total CVEs", summary["total_cves"]),
            ("Critical", summary["critical"]),
            ("High", summary["high"]),
            ("Medium", summary["medium"]),
            ("Low", summary["low"]),
            ("API errors", summary["api_errors"]),
        )
    )
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CVEWatchdog report</title><style>
:root{{--bg:#0b1020;--panel:#151c30;--text:#e8edf7;--muted:#9da9bd;--border:#2a3550}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--text);font:14px system-ui,sans-serif}}
main{{max-width:1400px;margin:auto;padding:32px}} h1{{margin-bottom:4px}} h2{{margin-top:0}} small,.cpe{{color:var(--muted)}}
.risk{{font-size:18px;font-weight:700}} .cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:24px 0}}
.card,section{{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:16px}} .card span{{display:block;font-size:24px;margin-top:8px}}
.filters{{display:flex;flex-wrap:wrap;gap:12px;align-items:end;margin:24px 0}} .filters label{{display:grid;gap:6px;color:var(--muted)}} .filters input,.filters select{{min-width:220px;padding:10px;border:1px solid var(--border);border-radius:6px;background:var(--panel);color:var(--text)}}
.software-list{{display:grid;grid-template-columns:1fr auto;gap:8px 12px;align-items:center;max-height:300px;overflow:auto;margin-top:12px}} .software-list label{{display:flex;gap:8px;align-items:center}} button{{padding:5px 10px;border:1px solid var(--border);border-radius:5px;background:var(--bg);color:var(--text);cursor:pointer}}
section{{margin:16px 0}} .table-wrap{{overflow:auto}} table{{width:100%;border-collapse:collapse}} th,td{{padding:9px;text-align:left;border-top:1px solid var(--border);vertical-align:top}}
.severity{{font-weight:700}} .critical{{color:#ff5c7a}} .high{{color:#ff8c69}} .medium{{color:#ffd166}} .low{{color:#72d6a0}} .unknown{{color:var(--muted)}}
</style></head><body><main><h1>CVEWatchdog report</h1><p class="risk">{html.escape(summary["risk_level"])}</p>
<section class="software-summary"><h2>Vulnerable software</h2><button type="button" id="software-all">Select all</button> <button type="button" id="software-none">Select none</button><div class="software-list">{"".join(software_choices) or "None"}</div></section>
<div class="cards">{cards}</div>
<div class="filters"><label>Search<input id="report-search" type="search" placeholder="Software, CPE, CVE, description"></label>
<label>Severity<select id="severity-filter"><option value="">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="unknown">Unknown</option></select></label>
<label>Vulnerability type<select id="type-filter"><option value="">All types</option><option value="lpe">LPE</option><option value="rce">RCE</option><option value="privilege-escalation">Privilege escalation</option><option value="dos">DoS</option><option value="information-disclosure">Information disclosure</option><option value="authentication-bypass">Authentication bypass</option><option value="xss">XSS</option><option value="sql-injection">SQL injection</option><option value="path-traversal">Path traversal</option><option value="other">Other</option></select></label>
<span id="visible-count"></span></div>{"".join(sections) or '<section><h2>No version-confirmed vulnerabilities found</h2></section>'}
</main><script>
const search=document.getElementById('report-search'), severity=document.getElementById('severity-filter'), type=document.getElementById('type-filter'), count=document.getElementById('visible-count'), software=[...document.querySelectorAll('.software-choice')];
function filterReport(){{let visible=0,query=search.value.trim().toLowerCase(),selected=new Set(software.filter(choice=>choice.checked).map(choice=>choice.value));document.querySelectorAll('.report-section').forEach(section=>{{let sectionRows=0,context=(section.querySelector('h2').textContent+' '+section.querySelector('.cpe').textContent).toLowerCase();section.querySelectorAll('tbody tr').forEach(row=>{{let show=selected.has(section.dataset.software)&&(!query||(context+' '+row.textContent).toLowerCase().includes(query))&&(!severity.value||row.dataset.severity===severity.value)&&(!type.value||row.dataset.types.split(' ').includes(type.value));row.hidden=!show;if(show){{visible++;sectionRows++;}}}});section.hidden=sectionRows===0;}});count.textContent=visible+' CVE shown';}}
search.addEventListener('input',filterReport);severity.addEventListener('change',filterReport);type.addEventListener('change',filterReport);software.forEach(choice=>choice.addEventListener('change',filterReport));
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
