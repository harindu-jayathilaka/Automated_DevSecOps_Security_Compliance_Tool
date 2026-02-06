import json
import os
from datetime import datetime

from .models import (
    ComplianceResult, ComplianceFinding, ComplianceReport,
    NISTControl, MappingType, MappingConfidence, 
    get_control_name, get_control_family
)


class MappingRegistry:
    
    def __init__(self, mappings_dir="data"):
        self.mappings_dir = mappings_dir
        
        self.semgrep_mappings = {}
        self.checkov_mappings = {}
        self.gitleaks_mappings = {}
        self.cwe_mappings = {}
        
        self._load_all_mappings()
    
    def _load_all_mappings(self):
        #Semgrep 
        semgrep_path = os.path.join(self.mappings_dir, "semgrep_nist_mapped.json")
        if os.path.exists(semgrep_path):
            self.semgrep_mappings = self._load_semgrep_mappings(semgrep_path)
            print(f"Loaded {len(self.semgrep_mappings)} Semgrep mappings")
        else:
            print(f"Warning: Semgrep mapping file not found.")
        
        #Checkov
        checkov_path = os.path.join(self.mappings_dir, "checkov_classified.json")
        if os.path.exists(checkov_path):
            self.checkov_mappings = self._load_checkov_mappings(checkov_path)
            print(f"Loaded {len(self.checkov_mappings)} Checkov mappings")
        else:
            print(f"Warning: Checkov mapping file not found.")
        
        # GitLeaks
        gitleaks_path = os.path.join(self.mappings_dir, "gitleaks_nist_mapping.json")
        if os.path.exists(gitleaks_path):
            self.gitleaks_mappings = self._load_gitleaks_mappings(gitleaks_path)
            print(f"Loaded {len(self.gitleaks_mappings)} GitLeaks mappings")
        else:
            print(f"Warning: GitLeaks mapping file not found.")
        
        #CWE to NIST
        cwe_path = os.path.join(self.mappings_dir, "cwe_to_nist_mapping.json")
        if os.path.exists(cwe_path):
            self.cwe_mappings = self._load_cwe_mappings(cwe_path)
            print(f"Loaded {len(self.cwe_mappings)} CWE mappings")
        else:
            print(f"Warning: CWE mapping file not found.")
        
        total = (len(self.semgrep_mappings) + len(self.checkov_mappings) + 
                 len(self.gitleaks_mappings) + len(self.cwe_mappings))
        print(f"Total mappings loaded: {total}")
    
    def _load_semgrep_mappings(self, path):
        mappings = {}
        try:
            with open(path, 'r') as f:
                data = json.load(f)
            
            for rule in data.get('rules', []):
                rule_id = rule.get('rule_id')
                if rule_id:
                    primary = rule.get('nist_controls', [])
                    secondary = rule.get('secondary_controls', [])
                    all_controls = primary + [c for c in secondary if c not in primary]
                    
                    mappings[rule_id] = {
                        'nist_controls': all_controls,
                        'primary_controls': primary,
                        'secondary_controls': secondary,
                        'nist_control_names': rule.get('nist_control_names', []),
                        'cwe_ids': rule.get('cwe_ids', []),
                        'mapping_confidence': rule.get('mapping_confidence', 'HIGH'),
                        'source': 'semgrep_nist_mapped.json'
                    }
        except Exception as e:
            print(f"Error: Failed to load Semgrep mappings - {e}")
        
        return mappings

    def _load_checkov_mappings(self, path):
        mappings = {}
        try:
            with open(path, 'r') as f:
                data = json.load(f)

            rules = data if isinstance(data, list) else data.get('rules', [])

            for rule in rules:
                rule_id = rule.get('rule_id')
                if rule_id:
                    mappings[rule_id] = {
                        'nist_controls': rule.get('nist_controls', []),
                        'nist_control_names': rule.get('nist_control_names', []),
                        'security_domains': rule.get('security_domains', []),
                        'policy': rule.get('policy', ''),
                        'mapping_confidence': rule.get('mapping_confidence', 'HIGH'),
                        'source': 'checkov_classified.json'
                    }
        except Exception as e:
            print(f"Error: Failed to load Checkov mappings - {e}")

        return mappings

    def _load_gitleaks_mappings(self, path):
        mappings = {}
        try:
            with open(path, 'r') as f:
                data = json.load(f)
            
            for rule in data.get('rules', []):
                rule_id = rule.get('rule_id')
                if rule_id:
                    mappings[rule_id] = {
                        'nist_controls': rule.get('nist_controls', []),
                        'cwe_ids': rule.get('cwe_ids', []),
                        'cwe_name': rule.get('cwe_name', ''),
                        'mapping_rationale': rule.get('nist_rationale', ''),
                        'mapping_confidence': rule.get('mapping_confidence', 'HIGH'),
                        'source': 'gitleaks_nist_mapping.json'
                    }
        except Exception as e:
            print(f"Error: Failed to load GitLeaks mappings - {e}")
        
        return mappings
    
    def _load_cwe_mappings(self, path):
        mappings = {}
        try:
            with open(path, 'r') as f:
                data = json.load(f)
            
            items = data if isinstance(data, list) else data.get('mappings', [])
            
            for item in items:
                cwe_id_field = item.get('cwe_id', [])
                if isinstance(cwe_id_field, list) and cwe_id_field:
                    cwe_id = cwe_id_field[0]
                elif isinstance(cwe_id_field, str):
                    cwe_id = cwe_id_field
                else:
                    continue
                
                if cwe_id:
                    primary = item.get('primary_controls', [])
                    secondary = item.get('secondary_controls', [])
                    all_controls = primary + [c for c in secondary if c not in primary]
                    
                    mappings[cwe_id] = {
                        'nist_controls': all_controls,
                        'primary_controls': primary,
                        'secondary_controls': secondary,
                        'cwe_name': item.get('cwe_name', ''),
                        'rationale': item.get('rationale', ''),
                        'mapping_confidence': item.get('mapping_confidence', 'HIGH'),
                        'source': 'cwe_to_nist_mapping.json'
                    }
        except Exception as e:
            print(f"Error: Failed to load CWE mappings - {e}")
        
        return mappings
    
    def get_semgrep_mapping(self, rule_id):
        return self.semgrep_mappings.get(rule_id)
    
    def get_checkov_mapping(self, rule_id):
        return self.checkov_mappings.get(rule_id)
    
    def get_gitleaks_mapping(self, rule_id):
        return self.gitleaks_mappings.get(rule_id)
    
    def get_cwe_mapping(self, cwe_id):
        if not cwe_id.startswith('CWE-'):
            cwe_id = f"CWE-{cwe_id}"
        return self.cwe_mappings.get(cwe_id)
    
    def get_mapping_stats(self):
        return {
            'semgrep_rules': len(self.semgrep_mappings),
            'checkov_rules': len(self.checkov_mappings),
            'gitleaks_rules': len(self.gitleaks_mappings),
            'cwe_mappings': len(self.cwe_mappings),
            'total': (len(self.semgrep_mappings) + len(self.checkov_mappings) + 
                     len(self.gitleaks_mappings) + len(self.cwe_mappings))
        }


class ComplianceMapper:
    def __init__(self, mappings_dir="data"):
        self.registry = MappingRegistry(mappings_dir)
        print(f"\nComplianceMapper initialized with {self.registry.get_mapping_stats()}")
    
    def map_finding(self, finding):
        if hasattr(finding, 'tool'):
            tool = finding.tool
            rule_id = finding.rule_id
            cwe_ids = finding.cwe_ids if hasattr(finding, 'cwe_ids') else []
        else:
            tool = finding.get('tool', '')
            rule_id = finding.get('rule_id', '')
            cwe_ids = finding.get('cwe_ids', [])
        
        primary_result = self._try_primary_mapping(tool, rule_id)
        if primary_result:
            return primary_result
        
        if cwe_ids:
            secondary_result = self._try_secondary_mapping(cwe_ids)
            if secondary_result:
                return secondary_result
        
        return ComplianceResult(
            mapped=False,
            mapping_type=MappingType.UNMAPPED,
            confidence=MappingConfidence.NONE,
            nist_controls=[],
            primary_nist_controls=[],
            secondary_nist_controls=[],
            mapping_source=None,
            mapping_rationale="No direct rule mapping or CWE mapping found"
        )
    
    def _try_primary_mapping(self, tool, rule_id):
        ##direct rule-to-NIST mapping (Layer 1)
        mapping = None
        
        if tool == 'semgrep':
            mapping = self.registry.get_semgrep_mapping(rule_id)
        elif tool == 'checkov':
            mapping = self.registry.get_checkov_mapping(rule_id)
        elif tool == 'gitleaks':
            mapping = self.registry.get_gitleaks_mapping(rule_id)

        if mapping and mapping.get('nist_controls'):
            nist_controls = self._create_nist_controls(mapping['nist_controls'])
            
            primary_controls = self._create_nist_controls(mapping.get('primary_controls', []))
            secondary_controls = self._create_nist_controls(mapping.get('secondary_controls', []))

            rationale = mapping.get('mapping_rationale', '')
            if isinstance(rationale, list):
                rationale = '; '.join(rationale) if rationale else None
            elif not rationale:
                rationale = None
            
            return ComplianceResult(
                mapped=True,
                mapping_type=MappingType.PRIMARY,
                confidence=MappingConfidence.HIGH,
                nist_controls=nist_controls,
                primary_nist_controls=primary_controls,
                secondary_nist_controls=secondary_controls,
                mapping_source=mapping.get('source'),
                mapping_rationale=rationale
            )
        
        return None
    
    def _try_secondary_mapping(self, cwe_ids):
        ##CWE-based NIST mapping (Layer 2)
        all_controls = []
        all_primary_controls = []      
        all_secondary_controls = [] 
        all_rationales = []
        source = None
        matched_cwes = []
        
        for cwe_id in cwe_ids:
            normalized_cwe = self._normalize_cwe_id(cwe_id)
            
            mapping = self.registry.get_cwe_mapping(normalized_cwe)
            if mapping and mapping.get('nist_controls'):
                matched_cwes.append(normalized_cwe)
                source = mapping.get('source')
                
                for control_id in mapping['nist_controls']:
                    if control_id not in [c.control_id for c in all_controls]:
                        all_controls.append(NISTControl(
                            control_id=control_id,
                            control_name=get_control_name(control_id),
                            family=get_control_family(control_id)
                        ))
                            
                # Add primary controls
                for control_id in mapping.get('primary_controls', []):
                    if control_id not in [c.control_id for c in all_primary_controls]:
                        all_primary_controls.append(NISTControl(
                            control_id=control_id,
                            control_name=get_control_name(control_id),
                            family=get_control_family(control_id)
                        ))
                
                # Add secondary controls
                for control_id in mapping.get('secondary_controls', []):
                    if control_id not in [c.control_id for c in all_secondary_controls]:
                        all_secondary_controls.append(NISTControl(
                            control_id=control_id,
                            control_name=get_control_name(control_id),
                            family=get_control_family(control_id)
                        ))
            
                if mapping.get('rationale'):
                    all_rationales.append(f"{normalized_cwe}: {mapping['rationale']}")
        
        if all_controls:
            return ComplianceResult(
                mapped=True,
                mapping_type=MappingType.SECONDARY,
                confidence=MappingConfidence.MEDIUM,
                nist_controls=all_controls,
                primary_nist_controls=all_primary_controls,
                secondary_nist_controls=all_secondary_controls,
                mapping_source=source,
                mapping_rationale='; '.join(all_rationales) if all_rationales else None,
                cwe_used=matched_cwes
            )
        
        return None
    
    def _normalize_cwe_id(self, cwe_id):
        if not cwe_id:
            return ""
        
        if ':' in cwe_id:
            cwe_id = cwe_id.split(':')[0].strip()
        
        if not cwe_id.upper().startswith('CWE-'):
            cwe_id = f"CWE-{cwe_id}"
        
        return cwe_id.upper()
    
    def _create_nist_controls(self, control_ids):
        controls = []
        for control_id in control_ids:
            controls.append(NISTControl(
                control_id=control_id,
                control_name=get_control_name(control_id),
                family=get_control_family(control_id)
            ))
        return controls
    
    def map_all_findings(self, findings):
        compliance_findings = []
        
        for finding in findings:
            compliance_result = self.map_finding(finding)
            
            if hasattr(finding, 'finding_id'):
                compliance_finding = ComplianceFinding(
                    finding_id=finding.finding_id,
                    tool=finding.tool,
                    rule_id=finding.rule_id,
                    title=finding.title,
                    description=finding.description,
                    severity=finding.severity.value if hasattr(finding.severity, 'value') else finding.severity,
                    file_path=finding.file_path,
                    line_start=finding.line_start,
                    line_end=finding.line_end,
                    cwe_ids=finding.cwe_ids if hasattr(finding, 'cwe_ids') else [],
                    categories=finding.categories if hasattr(finding, 'categories') else [],
                    owasp_categories=finding.owasp_categories if hasattr(finding, 'owasp_categories') else [],
                    code_snippet=finding.code_snippet if hasattr(finding, 'code_snippet') else None,
                    compliance=compliance_result
                )
            else:
                compliance_finding = ComplianceFinding(
                    finding_id=finding.get('finding_id', ''),
                    tool=finding.get('tool', ''),
                    rule_id=finding.get('rule_id', ''),
                    title=finding.get('title', ''),
                    description=finding.get('description', ''),
                    severity=finding.get('severity', ''),
                    file_path=finding.get('file_path', ''),
                    line_start=finding.get('line_start', 0),
                    line_end=finding.get('line_end', 0),
                    cwe_ids=finding.get('cwe_ids', []),
                    categories=finding.get('categories', []),
                    owasp_categories=finding.get('owasp_categories', []),
                    code_snippet=finding.get('code_snippet'),
                    compliance=compliance_result
                )
            
            compliance_findings.append(compliance_finding)
        
        return compliance_findings
    
    def generate_report(self, findings, scan_target):
        compliance_findings = self.map_all_findings(findings)
        
        total = len(compliance_findings)
        mapped = sum(1 for f in compliance_findings if f.compliance.mapped)
        unmapped = total - mapped
        primary = sum(1 for f in compliance_findings 
                     if f.compliance.mapping_type == MappingType.PRIMARY)
        secondary = sum(1 for f in compliance_findings 
                       if f.compliance.mapping_type == MappingType.SECONDARY)
        
        controls_count = {}
        families_count = {}
        for finding in compliance_findings:
            for control in finding.compliance.nist_controls:
                controls_count[control.control_id] = controls_count.get(control.control_id, 0) + 1
                families_count[control.family] = families_count.get(control.family, 0) + 1
        
        tools_used = list(set(f.tool for f in compliance_findings))
        
        report = ComplianceReport(
            scan_target=scan_target,
            scan_date=datetime.now().isoformat(),
            tools_used=tools_used,
            total_findings=total,
            mapped_findings=mapped,
            unmapped_findings=unmapped,
            primary_mappings=primary,
            secondary_mappings=secondary,
            controls_triggered=dict(sorted(controls_count.items(), key=lambda x: -x[1])),
            families_triggered=dict(sorted(families_count.items(), key=lambda x: -x[1])),
            findings=compliance_findings
        )
        
        return report
    
    def get_mapping_stats(self):
        return self.registry.get_mapping_stats()


if __name__ == "__main__":
    pass