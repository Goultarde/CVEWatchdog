import argparse
import subprocess
import sys
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
                timeout=10
            )
            
            if result.returncode == 0:
                if pm_name == "pacman":
                    software = parse_pacman_inventory(result.stdout)
                    print(f"{Colors.GREEN}✅ Found {len(software)} packages using pacman "
                          f"(ignoring {ignored} system packages){Colors.RESET}")
                    return software, ignored

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

if __name__ == "__main__":
    main()
