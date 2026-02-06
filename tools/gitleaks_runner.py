import subprocess
import json
import os


def run_gitleaks(target_pth, output):
    print(f" Running GitLeaks on: {target_pth}")
    
 
    os.makedirs(os.path.dirname(output), exist_ok=True)
    
    cmd = [
        "gitleaks",
        "detect",
        "--source", target_pth,
        "--report-format", "json",
        "--report-path", output,
        "--no-git"  # Scan files
    ]
    

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=300  # 10 minute timeout
    )

    findings_count = 0
    with open(output, 'r') as f:
        jsn_data = json.load(f)
        findings_count = len(jsn_data) if isinstance(jsn_data, list) else 0

    print(f" GitLeaks scan complete: {findings_count} findings")
    
    return {
        'success': True,
        'findings_count': findings_count,
        'output': output
    }
        
def parse_gitleaks_results(jsn_file):

    with open(jsn_file, 'r') as f:
        jsn_data = json.load(f)
    
    if not isinstance(jsn_data, list):
        return []
    
    findings = []
    
    for leak in jsn_data:
        finding = {
            'tool': 'gitleaks',
            'rule_id': leak.get('RuleID', 'unknown'),
            'message': f"Secret detected: {leak.get('Description', 'Unknown type')}",
            'severity': 'HIGH',  # All secrets mark as high severity
            'file_path': leak.get('File', ''),
            'line_start': leak.get('StartLine', 0),
            'line_end': leak.get('EndLine', 0),
            'secret_type': leak.get('RuleID', ''),
        }
        
        findings.append(finding)
    
    print(f"Parsed {len(findings)} GitLeaks findings")
    return findings

def test_gitleaks():
    print("Testing GitLeaks scanner")
    
    target = "test_code"
    output = "results/gitleaks_test.json"
    
    result = run_gitleaks(target, output)
    
    if result['success']:
        print(f"\n Scan successful!")
        print(f"Findings: {result['findings_count']}")
        
        findings = parse_gitleaks_results(output)
        
    else:
        print(f"\nScan failed: {result.get('error')}")


if __name__ == "__main__":
    test_gitleaks()
