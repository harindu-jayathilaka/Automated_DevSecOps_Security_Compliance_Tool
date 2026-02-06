import json
import subprocess
import os
import shutil

PATH_DEPENDENCY_CHECK= "./tools/dependency_check/dependency-check/bin/dependency-check.sh"
OUTPUT_FILE = "dependency-check-report.json"


def run_dependency_check(target_path, output="results/dependency_check.json"):
    print(f" Running Dependency Check on: {target_path}")
    
    output_pth = os.path.dirname(output) or "results"
    os.makedirs(output_pth, exist_ok=True)
    
    report_path = os.path.join(output_pth, OUTPUT_FILE)

    cmd = [
        PATH_DEPENDENCY_CHECK,
        "--scan", target_path,
        "--format", "JSON",
        "--out", output_pth,
        "--project", "security-scan",
        "--enableExperimental"
    ]
    
    print(f"Running command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=600  # 10 minute timeout 
        )

        if report_path != output:
            shutil.move(report_path, output)

        findings = parse_dependency_check_results(output)
        
        print(f"Dependency-Check scan complete: {len(findings)} findings")
        
        return {
            'success': True,
            'findings_count': len(findings),
            'output_file': output
        }

    except subprocess.TimeoutExpired:
        print("Error: scan timed out")
        return {
            'success': False,
            'error': 'Scan timed out',
            'findings_count': 0
        }
    except FileNotFoundError:
        print(f"Dependency-Check not found. Please install.")
        return {
            'success': False,
            'error': 'Dependency-Check not installed',
            'findings_count': 0
        }

def parse_dependency_check_results(report_path):
    findings = []

    try:
        with open(report_path, "r") as f:
            report = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: failed to parse report: {e}")
        return findings
    except Exception as e:
        print(f"Error: failed to load report: {e}")
        return findings

    for dependency in report.get("dependencies", []):
        file_path = dependency.get("filePath", dependency.get("fileName", "unknown"))
        file_name = dependency.get("fileName", "unknown")
        
        for vuln in dependency.get("vulnerabilities", []):
            vuln_name = vuln.get("name", "UNKNOWN")
            
            # extract cwe ids
            cwe_ids = []
            for cwe in vuln.get("cwes", []):
                if isinstance(cwe, str):
                    if cwe.startswith("CWE-"):
                        cwe_ids.append(cwe)
                    else:
                        cwe_ids.append(f"CWE-{cwe}")
                elif isinstance(cwe, dict):
                    cwe_id = cwe.get("id") or cwe.get("cweId")
                    if cwe_id:
                        if str(cwe_id).startswith("CWE-"):
                            cwe_ids.append(cwe_id)
                        else:
                            cwe_ids.append(f"CWE-{cwe_id}")

            severity = map_cvss_severity(vuln)
            
            finding = {
                'tool': 'dependency-check',
                'rule_id': vuln_name,
                'message': vuln.get("description", "Known vulnerability")[:500],
                'severity': severity,
                'file_path': file_path,
                'line_start': 0,
                'line_end': 0,
                'dependency': file_name,
                'cwe': cwe_ids,
                'cvss_score': get_cvss_score(vuln),
                'references': [ref.get("url") for ref in vuln.get("references", [])[:3] if ref.get("url")]
            }
            
            findings.append(finding)

    print(f"Parsed {len(findings)} Dependency-Check findings")
    return findings


def map_cvss_severity(vuln):  
    cvss_score = get_cvss_score(vuln)
    
    if cvss_score is None:
        severity_str = vuln.get("severity", "MEDIUM").upper()
        if severity_str in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            return severity_str
        return "MEDIUM"
    
    if cvss_score >= 9.0:
        return "CRITICAL"
    elif cvss_score >= 7.0:
        return "HIGH"
    elif cvss_score >= 4.0:
        return "MEDIUM"
    elif cvss_score > 0:
        return "LOW"
    else:
        return "INFO"


def get_cvss_score(vuln):
    if "cvssv3" in vuln:
        cvss_v3 = vuln["cvssv3"]
        if isinstance(cvss_v3, dict):
            return cvss_v3.get("baseScore") or cvss_v3.get("score")
        elif isinstance(cvss_v3, (int, float)):
            return float(cvss_v3)
    
    if "cvssv2" in vuln:
        cvss_v2 = vuln["cvssv2"]
        if isinstance(cvss_v2, dict):
            return cvss_v2.get("score") or cvss_v2.get("baseScore")
        elif isinstance(cvss_v2, (int, float)):
            return float(cvss_v2)
    
    if "cvssScore" in vuln:
        return float(vuln["cvssScore"])
    
    return None


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = "test_code"
    
    print(f"Testing Dependency-Check on: {target}")
    result = run_dependency_check(target, "results/dependency_check.json")
    print(f"Result: {result}")
    
    if result['success']:
        findings = parse_dependency_check_results("results/dependency_check.json")
        print(f"\nSample finding:")
        if findings:
            print(json.dumps(findings[0], indent=2))