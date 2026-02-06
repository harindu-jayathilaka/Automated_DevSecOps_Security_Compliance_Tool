from dataclasses import dataclass, field
from enum import Enum


class MappingType(Enum):
    PRIMARY = "PRIMARY"
    SECONDARY = "SECONDARY"
    UNMAPPED = "UNMAPPED"


class MappingConfidence(Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


@dataclass
class NISTControl:
    control_id: str
    control_name: str
    family: str
    
    def to_dict(self):
        return {
            'control_id': self.control_id,
            'control_name': self.control_name,
            'family': self.family
        }


@dataclass
class ComplianceResult:
    mapped: bool
    mapping_type: MappingType
    confidence: MappingConfidence
    nist_controls: list
    primary_nist_controls: list 
    secondary_nist_controls: list 
    mapping_source: str = None
    mapping_rationale: str = None
    cwe_used: list = None
    
    def to_dict(self):
        return {
            'mapped': self.mapped,
            'mapping_type': self.mapping_type.value,
            'confidence': self.confidence.value,
            'nist_controls': [ctrl.to_dict() for ctrl in self.nist_controls],
            'primary_nist_controls': [ctrl.to_dict() for ctrl in self.primary_nist_controls],
            'secondary_nist_controls': [ctrl.to_dict() for ctrl in self.secondary_nist_controls],
            'mapping_source': self.mapping_source,
            'mapping_rationale': self.mapping_rationale,
            'cwe_used': self.cwe_used
        }


@dataclass
class ComplianceFinding:
    finding_id: str
    tool: str
    rule_id: str
    title: str
    description: str
    severity: str
    file_path: str
    line_start: int
    line_end: int
    cwe_ids: list
    compliance: ComplianceResult
    code_snippet: str = None
    categories: list = field(default_factory=list)
    owasp_categories: list = field(default_factory=list)
    
    def to_dict(self):
        return {
            'finding_id': self.finding_id,
            'tool': self.tool,
            'rule_id': self.rule_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'file_path': self.file_path,
            'line_start': self.line_start,
            'line_end': self.line_end,
            'cwe_ids': self.cwe_ids,
            'categories': self.categories,
            'owasp_categories': self.owasp_categories,
            'code_snippet': self.code_snippet,
            'compliance': self.compliance.to_dict()
        }


@dataclass
class ComplianceReport:
    scan_target: str
    scan_date: str
    tools_used: list
    mapping_version: str = "1.0"
    nist_framework: str = "NIST SP 800-53 Rev 5"
    
    total_findings: int = 0
    mapped_findings: int = 0
    unmapped_findings: int = 0
    primary_mappings: int = 0
    secondary_mappings: int = 0
    
    controls_triggered: dict = field(default_factory=dict)
    families_triggered: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    
    def to_dict(self):
        return {
            'metadata': {
                'scan_target': self.scan_target,
                'scan_date': self.scan_date,
                'tools_used': self.tools_used,
                'nist_framework': self.nist_framework
            },
            'summary': {
                'total_findings': self.total_findings,
                'mapped_findings': self.mapped_findings,
                'unmapped_findings': self.unmapped_findings,
                'primary_mappings': self.primary_mappings,
                'secondary_mappings': self.secondary_mappings,
                'controls_triggered': self.controls_triggered,
                'families_triggered': self.families_triggered
            },
            'findings': [f.to_dict() for f in self.findings]
        }

##NIST Control Names (30 controls from mapping files)
NIST_CONTROL_NAMES = {
    'SI-2': 'Flaw Remediation',
    'SI-3': 'Malicious Code Protection',
    'SI-4': 'System Monitoring',
    'SI-5': 'Security Alerts, Advisories, and Directives',
    'SI-7': 'Software, Firmware, and Information Integrity',
    'SI-10': 'Information Input Validation',
    'SI-11': 'Error Handling',
    'SI-16': 'Memory Protection',
    'SI-17': 'Fail-Safe Procedures',
    
    'AC-2': 'Account Management',
    'AC-3': 'Access Enforcement',
    'AC-4': 'Information Flow Enforcement',
    'AC-5': 'Separation of Duties',
    'AC-6': 'Least Privilege',
    'AC-7': 'Unsuccessful Logon Attempts',
    'AC-17': 'Remote Access',
    
    'IA-2': 'Identification and Authentication (Organizational Users)',
    'IA-5': 'Authenticator Management',
    'IA-8': 'Identification and Authentication (Non-Organizational Users)',
    
    'SC-4': 'Information in Shared System Resources',
    'SC-7': 'Boundary Protection',
    'SC-8': 'Transmission Confidentiality and Integrity',
    'SC-12': 'Cryptographic Key Establishment and Management',
    'SC-13': 'Cryptographic Protection',
    'SC-18': 'Mobile Code',
    'SC-23': 'Session Authenticity',
    'SC-28': 'Protection of Information at Rest',
    
    'CM-2': 'Baseline Configuration',
    'CM-5': 'Access Restrictions for Change',
    'CM-6': 'Configuration Settings',
    'CM-7': 'Least Functionality',
}


def get_control_name(control_id):
    base_control = control_id.split('(')[0]
    return NIST_CONTROL_NAMES.get(base_control)


def get_control_family(control_id):
    if '-' in control_id:
        return control_id.split('-')[0]
    return control_id[:2]