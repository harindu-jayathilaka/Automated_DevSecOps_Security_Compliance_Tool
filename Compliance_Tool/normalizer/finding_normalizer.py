from models.finding import UnifiedFinding, Severity


class FindingNormalizer:
    def __init__(self):
        self.severity_map = self._build_severity_map()
    
    def _build_severity_map(self):
        return {
            'ERROR': Severity.HIGH,
            'WARNING': Severity.MEDIUM,
            'INFO': Severity.INFO,
            
            'CRITICAL': Severity.CRITICAL,
            'HIGH': Severity.HIGH,
            'MEDIUM': Severity.MEDIUM,
            'LOW': Severity.LOW,
            
            # GitLeaks
            'SECRET': Severity.HIGH,
        }
    
    def normalize_all(self, raw_findings):
        normalized = []
        
        for raw in raw_findings:

            tool = raw.get('tool', 'unknown')
            
            if tool == 'semgrep':
                unified = self.normalize_semgrep(raw)
            elif tool == 'checkov':
                unified = self.normalize_checkov(raw)
            elif tool == 'gitleaks':
                unified = self.normalize_gitleaks(raw)
            elif tool == 'dependency-check':
                unified = self.normalize_dependency_check(raw)
            else:
                print(f"Warning: Unknown tool '{tool}'")
                continue
            
            normalized.append(unified)

        
        print(f"Normalized {len(normalized)}/{len(raw_findings)} findings")
        return normalized
    
    def normalize_semgrep(self, raw):
        finding_id = UnifiedFinding.generate_id(
            tool='semgrep',
            rule_id=raw['rule_id'],
            file_path=raw['file_path'],
            line=raw['line_start']
        )
        
        severity_str = raw.get('severity', 'INFO').upper()
        severity = self.severity_map.get(severity_str, Severity.MEDIUM)
        
        title = self.extract_title(raw['rule_id'])
        
        return UnifiedFinding(
            finding_id=finding_id,
            tool='semgrep',
            rule_id=raw['rule_id'],
            title=title,
            description=raw.get('message', ''),
            severity=severity,
            file_path=raw['file_path'],
            line_start=raw.get('line_start', 0),
            line_end=raw.get('line_end', 0),
            code_snippet=raw.get('code_snippet'),
            cwe_ids=raw.get('cwe', []),
            owasp_categories=raw.get('owasp', []),
            categories=['code-vulnerability']
        )
    
    def normalize_checkov(self, raw):
        finding_id = UnifiedFinding.generate_id(
            tool='checkov',
            rule_id=raw['rule_id'],
            file_path=raw['file_path'],
            line=raw['line_start']
        )
        
        severity_str = (raw.get('severity') or 'HIGH').upper()
        severity = self.severity_map.get(severity_str, Severity.HIGH)
        
        return UnifiedFinding(
            finding_id=finding_id,
            tool='checkov',
            rule_id=raw['rule_id'],
            title=raw.get('message', raw['rule_id']),
            description=raw.get('message', ''),
            severity=severity,
            file_path=raw['file_path'],
            line_start=raw.get('line_start', 0),
            line_end=raw.get('line_end', 0),
            categories=['infrastructure', 'misconfiguration']
        )
    
    def normalize_gitleaks(self, raw):
        finding_id = UnifiedFinding.generate_id(
            tool='gitleaks',
            rule_id=raw['rule_id'],
            file_path=raw['file_path'],
            line=raw['line_start']
        )
        
        # All secrets marks as HIGH 
        severity = Severity.HIGH
        
        secret_type = raw.get('secret_type', 'Unknown')
        title = f"Exposed Secret: {secret_type}"
        
        return UnifiedFinding(
            finding_id=finding_id,
            tool='gitleaks',
            rule_id=raw['rule_id'],
            title=title,
            description=raw.get('message', f"Detected exposed {secret_type}"),
            severity=severity,
            file_path=raw['file_path'],
            line_start=raw.get('line_start', 0),
            line_end=raw.get('line_end', 0),
            categories=['exposed-secrets']
        )
    
    def normalize_dependency_check(self, raw):
        finding_id = UnifiedFinding.generate_id(
            tool='dependency-check',
            rule_id=raw['rule_id'],
            file_path=raw['file_path'],
            line=0
        )
        
        severity_str = raw.get('severity', 'MEDIUM').upper()
        severity = self.severity_map.get(severity_str, Severity.MEDIUM)
        
        dependency_name = raw.get('dependency', 'Unknown')
        cve_id = raw.get('rule_id', 'Unknown CVE')
        title = f"Vulnerable Dependency: {dependency_name} ({cve_id})"
        
        return UnifiedFinding(
            finding_id=finding_id,
            tool='dependency-check',
            rule_id=raw['rule_id'],
            title=title,
            description=raw.get('message', 'Known vulnerability in dependency')[:200],
            severity=severity,
            file_path=raw['file_path'],
            line_start=0,
            line_end=0,
            categories=['vulnerable-dependency'],
            cwe_ids=raw.get('cwe', []) if isinstance(raw.get('cwe'), list) else []
        )
    
    def extract_title(self, rule_id):
        parts = rule_id.split('.')
        if parts:
            last_part = parts[-1].replace('-', ' ').replace('_', ' ').title()
            return last_part
        return rule_id


if __name__ == "__main__":
    pass
