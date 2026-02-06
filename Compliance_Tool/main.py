import sys
import json
from pathlib import Path
from datetime import datetime

from tools.semgrep_runner import run_semgrep, parse_semgrep_results
from tools.checkov_runner import run_checkov, parse_checkov_results
from tools.gitleaks_runner import run_gitleaks, parse_gitleaks_results
from tools.dependency_check_runner import run_dependency_check, parse_dependency_check_results

from normalizer.finding_normalizer import FindingNormalizer

from compliance import ComplianceMapper


def scan_project(target_path, mappings_dir="data"):
    print("\n" + "="*70)
    print("Automated Security Compliance Tool - Automated Compliance Mapping")
    print("="*70)
    print(f"Target: {target_path}")
    print(f"Mappings: {mappings_dir}")
    print(f"Framework: NIST SP 800-53 Rev 5\n")
    
    raw_findings = {}
    summary = {
        'target_path': target_path,
        'scan_date': datetime.now().isoformat(),
        'tools_run': 0,
        'tools_successful': 0,
        'total_raw_findings': 0,
        'total_normalized_findings': 0,
        'total_mapped_findings': 0,
        'total_unmapped_findings': 0
    }
    
    #STEP 1: RUN TOOLS
    print("=" * 70)
    print(" STEP 1: RUNNING SCANNING TOOLS")
    print("=" * 70)
    
    #Semgrep (SAST)
    print("\nRunning Semgrep (SAST)")
    result = run_semgrep(target_path, "results/semgrep.json")
    if result['success']:
        findings = parse_semgrep_results("results/semgrep.json")
        raw_findings['semgrep'] = findings
        summary['tools_successful'] += 1
        print(f"    Found {len(findings)} findings")
    else:
        print(f"    Failed: {result.get('error', 'Unknown error')}")
    summary['tools_run'] += 1
    
    #Checkov (IaC)
    print("\nRunning Checkov (IaC)")
    result = run_checkov(target_path, "results/checkov.json")
    if result['success']:
        findings = parse_checkov_results("results/checkov.json")
        raw_findings['checkov'] = findings
        summary['tools_successful'] += 1
        print(f"    Found {len(findings)} findings")
    else:
        print(f"    Failed: {result.get('error', 'Unknown error')}")
    summary['tools_run'] += 1
    
    #GitLeaks (Secrets)
    print("\nRunning GitLeaks (Secrets)")
    result = run_gitleaks(target_path, "results/gitleaks.json")
    if result['success']:
        findings = parse_gitleaks_results("results/gitleaks.json")
        raw_findings['gitleaks'] = findings
        summary['tools_successful'] += 1
        print(f"    Found {len(findings)} findings")
    else:
        print(f"    Failed: {result.get('error', 'Unknown error')}")
    summary['tools_run'] += 1
    
    #Dependency-Check (SCA)
    print("\nRunning Dependency-Check (SCA)")
    result = run_dependency_check(target_path, "results/dependency_check.json")
    if result['success']:
        findings = parse_dependency_check_results("results/dependency_check.json")
        raw_findings['dependency_check'] = findings
        summary['tools_successful'] += 1
        print(f"    Found {len(findings)} findings")
    else:
        print(f"    Failed: {result.get('error', 'Unknown error')}")
    summary['tools_run'] += 1
    
    summary['total_raw_findings'] = sum(len(f) for f in raw_findings.values())
    
    #STEP 2: NORMALIZE 
    print("\n" + "=" * 70)
    print(" STEP 2: NORMALIZING FINDINGS")
    print("=" * 70)
    
    all_raw_findings = []
    for tool_findings in raw_findings.values():
        all_raw_findings.extend(tool_findings)
    
    normalizer = FindingNormalizer()
    normalized_findings = normalizer.normalize_all(all_raw_findings)
    summary['total_normalized_findings'] = len(normalized_findings)
    
    print(f"\n    Normalized {len(normalized_findings)} findings from {len(raw_findings)} tools")
    
    #STEP 3: MAP TO NIST
    print("\n" + "=" * 70)
    print(" STEP 3: MAPPING TO NIST SP 800-53 REV 5 CONTROLS")
    print("=" * 70)
    
    mapper = ComplianceMapper(mappings_dir=mappings_dir)
    
    stats = mapper.get_mapping_stats()
    print(f"\n  Loaded mappings:")
    print(f"      - Semgrep rules:  {stats['semgrep_rules']}")
    print(f"      - Checkov rules:  {stats['checkov_rules']}")
    print(f"      - GitLeaks rules: {stats['gitleaks_rules']}")
    print(f"      - CWE mappings:   {stats['cwe_mappings']}")
    print(f"      - Total:          {stats['total']}")
    
    compliance_report = mapper.generate_report(normalized_findings, target_path)
    
    summary['total_mapped_findings'] = compliance_report.mapped_findings
    summary['total_unmapped_findings'] = compliance_report.unmapped_findings
    
    print(f"\n    Mapping results:")
    print(f"       Mapped:   {compliance_report.mapped_findings} findings")
    print(f"       Unmapped: {compliance_report.unmapped_findings} findings")
    print(f"       Primary:  {compliance_report.primary_mappings} (direct rule match)")
    print(f"       Secondary: {compliance_report.secondary_mappings} (CWE fallback)")
    
    #STEP 4: SAVE REPORTS
    print("\n" + "=" * 70)
    print(" STEP 4: GENERATING REPORTS")
    print("=" * 70)
    
    output_r = "results/all_raw_findings.json"
    with open(output_r, 'w') as f:
        json.dump({
            'summary': summary,
            'findings': raw_findings
        }, f, indent=2)
    print(f"\n     Raw findings:        {output_r}")
    
    normalized_out = "results/all_normalized_findings.json"
    with open(normalized_out, 'w') as f:
        json.dump({
            'summary': summary,
            'findings': [f.to_dict() for f in normalized_findings]
        }, f, indent=2)
    print(f"     Normalized findings: {normalized_out}")
    
    compliance_out = "results/compliance_report.json"
    with open(compliance_out, 'w') as f:
        json.dump(compliance_report.to_dict(), f, indent=2)
    print(f"     Compliance_report:   {compliance_out}")
    
    #STEP 5: Finale
    print("\n" + "=" * 70)
    print(" Summary")

    print(f"\n  Scan Target: {target_path}")
    print(f"  Scan Date:   {summary['scan_date']}")
    
    print(f"\n  Tool Execution:")
    print(f"    - Tools run:        {summary['tools_run']}")
    print(f"    - Tools successful: {summary['tools_successful']}")
    
    print(f"\n  Findings:")
    print(f"    - Raw findings:        {summary['total_raw_findings']}")
    print(f"    - Normalized findings: {summary['total_normalized_findings']}")
    
    print(f"\n  Compliance Mapping:")
    print(f"    - Mapped to NIST:   {summary['total_mapped_findings']}")
    print(f"    - Unmapped:         {summary['total_unmapped_findings']}")
    
    if summary['total_normalized_findings'] > 0:
        mapping_rate = summary['total_mapped_findings'] / summary['total_normalized_findings'] * 100
    else:
        mapping_rate = 0
    print(f"    - Mapping rate:     {mapping_rate:.1f}%")
    
    print(f"\n  Findings by Tool:")
    for tool, findings in raw_findings.items():
        print(f"    - {tool}: {len(findings)}")
    
    print(f"\n  Findings by Severity:")
    severity_counts = {}
    for finding in normalized_findings:
        sev = finding.severity.value if hasattr(finding.severity, 'value') else finding.severity
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        count = severity_counts.get(severity, 0)
        if count > 0:
            print(f"    - {severity}: {count}")
    
    print(f"\n  Top NIST Controls Triggered:")
    for control, count in list(compliance_report.controls_triggered.items())[:10]:
        print(f"    - {control}: {count} findings")
    
    print(f"\n  NIST Families Covered:")
    family_names = {
        'SI': 'System and Information Integrity',
        'AC': 'Access Control',
        'IA': 'Identification and Authentication',
        'SC': 'System and Communications Protection',
        'CM': 'Configuration Management'
    }
    for family, count in compliance_report.families_triggered.items():
        name = family_names.get(family, family)
        print(f"    - {family} ({name}): {count} findings")
    
    print("\n" + "=" * 70)
    
    return raw_findings, normalized_findings, compliance_report, summary


def print_unmapped_findings(compliance_report):
    """Print unmapped findings for debugging/analysis."""
    unmapped = [f for f in compliance_report.findings if not f.compliance.mapped]
    
    if not unmapped:
        print("\n All findings were successfully mapped to NIST controls!")
        return
    
    print(f"\n  UNMAPPED FINDINGS ({len(unmapped)}):")
    print("=" * 60)
    
    for finding in unmapped:
        print(f"\n  Tool: {finding.tool}")
        print(f"  Rule: {finding.rule_id}")
        print(f"  CWEs: {finding.cwe_ids}")
        print(f"  File: {finding.file_path}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_path = sys.argv[1]
    
    if not Path(target_path).exists():
        print(f"Error: Empty Target path: {target_path}")
        sys.exit(1)
    
    mappings_dir = "data"
    if not Path(mappings_dir).exists():
        print(f"Warning: Mappings directory not found: {mappings_dir}")
        print("Creating directory and expecting mapping files...")
        Path(mappings_dir).mkdir(exist_ok=True)
    
    raw, normalized, compliance_report, summary = scan_project(target_path, mappings_dir)

    print_unmapped_findings(compliance_report)
    
    if summary['tools_successful'] == 0:
        print("\nAll tools failed!")
        sys.exit(1)
    elif summary['total_normalized_findings'] > 0:
        print(f"\nFound {summary['total_normalized_findings']} security issues")
        print(f"   {summary['total_mapped_findings']} mapped to NIST controls")
        sys.exit(0)
    else:
        print("\nNo security issues found!")
        sys.exit(0)