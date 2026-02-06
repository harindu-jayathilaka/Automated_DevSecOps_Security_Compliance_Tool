import subprocess
import json
import os
import shutil


def run_checkov(target_pth, output_file):
    print(f"Running Checkov on: {target_pth}")

    output_direc = os.path.dirname(output_file)

    cmd = [
        "checkov",
        "-d", target_pth,              # scan directory
        "--output", "json",             # Output format
        "--output-file-path", output_direc or ".",  
        "--soft-fail",                  
        "--quiet"                       
    ]
    

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=600   
    )
    
    actual_output = os.path.join(output_direc or ".", "results_json.json")
    
    if os.path.exists(actual_output):
        if actual_output != output_file:
            shutil.move(actual_output, output_file)
    
    findings = parse_checkov_results(output_file)
    findings_count = len(findings)
    
    print(f"Checkov scan complete: {findings_count} findings")
    
    return {
        'success': True,
        'findings_count': findings_count,
        'output_file': output_file
    }
    

def parse_checkov_results(json_in):

    with open(json_in, 'r') as f:
        data = json.load(f)
    
    findings = []
    
    all_failed_checks = []
    
    if isinstance(data, list):
        for framework_result in data:
            if isinstance(framework_result, dict):
                results = framework_result.get('results', {})
                if isinstance(results, dict):
                    failed = results.get('failed_checks', [])
                    if isinstance(failed, list):
                        all_failed_checks.extend(failed)
    
    elif isinstance(data, dict):
        results = data.get('results', {})
        if isinstance(results, dict):
            failed = results.get('failed_checks', [])
            if isinstance(failed, list):
                all_failed_checks.extend(failed)
        elif isinstance(results, list):
            for item in results:
                if isinstance(item, dict) and 'failed_checks' in item:
                    all_failed_checks.extend(item.get('failed_checks', []))
    
    for check in all_failed_checks:
        if not isinstance(check, dict):
            continue
            
        line_range = check.get('file_line_range', [0, 0])
        if isinstance(line_range, list) and len(line_range) >= 1:
            line_strt = line_range[0] if line_range[0] else 0
            line_end = line_range[-1] if line_range[-1] else line_strt
        else:
            line_strt = 0
            line_end = 0
        
        finding = {
            'tool': 'checkov',
            'rule_id': check.get('check_id', 'unknown'),
            'message': check.get('check_name', ''),
            'severity': check.get('severity', 'HIGH'),  # Use provided or default: HIGH
            'file_path': check.get('file_path', ''),
            'line_start': line_strt,
            'line_end': line_end,
            'resource': check.get('resource', ''),
            'guideline': check.get('guideline', ''),
            'check_type': check.get('check_type', ''),  
        }
        
        findings.append(finding)
    
    print(f"Parsed {len(findings)} Checkov findings")
    return findings
        


def test_checkov():
    print("Testing Checkov")
    
    target = "test_code"
    output = "results/checkov_test.json"

    result = run_checkov(target, output)
    
    if result['success']:
        print(f"Scan successful!")
        print(f"Findings: {result['findings_count']}")
        
        findings = parse_checkov_results(output)
        
    else:
        print(f"\n Scan failed: {result.get('error')}")


if __name__ == "__main__":
    test_checkov()
