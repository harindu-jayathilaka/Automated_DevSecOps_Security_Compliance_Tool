import shutil
import subprocess
import json
import os
from pathlib import Path

def run_semgrep(target_path, output_file):
    print(f" Running Semgrep on: {target_path}")

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    cmd = [
        "semgrep",
        "--config=auto",      # automatic rule selection
        "--json",             # JSON outputS
        "-o", output_file,    
        "--quiet",            
        target_path
    ]
    

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=600 
    )
    
    if not os.path.exists(output_file):
        return {'success': False, 'error': 'No output file created'}
    
    with open(output_file, 'r') as f:
        data = json.load(f)
        findings_count = len(data.get('results', []))
    
    print(f" Semgrep scan complete: {findings_count} findings")
    
    return {
        'success': True,
        'findings_count': findings_count,
        'output_file': output_file
    }

def parse_semgrep_results(jsn_file):

    if not os.path.exists(jsn_file):
        print(f"File not found: {jsn_file}")
        return []

    with open(jsn_file, 'r') as f:
        data = json.load(f)
    
    findings = []
    
    for result in data.get('results', []):
        finding = {
            'tool': 'semgrep',
            'rule_id': result.get('check_id', 'unknown'),
            'message': result.get('extra', {}).get('message', ''),
            'severity': result.get('extra', {}).get('severity', 'INFO'),
            'file_path': result.get('path', ''),
            'line_start': result.get('start', {}).get('line', 0),
            'line_end': result.get('end', {}).get('line', 0),
            'code_snippet': result.get('extra', {}).get('lines', ''),
        }
        
        metadata = result.get('extra', {}).get('metadata', {})
        finding['cwe'] = metadata.get('cwe', [])
        finding['owasp'] = metadata.get('owasp', [])
        
        findings.append(finding)
    
    print(f"Parsed {len(findings)} Semgrep findings")
    return findings
    

def test_semgrep():
    print("Testing Semgrep Integration")
    
    target = "test_code"
    output = "results/semgrep_test.json"
    
    result = run_semgrep(target, output)
    
    if result['success']:
        print(f"Findings: {result['findings_count']}")
        
        findings = parse_semgrep_results(output)
    
    else:
        print(f"\nScan failed: {result.get('error')}")


if __name__ == "__main__":
    test_semgrep()
