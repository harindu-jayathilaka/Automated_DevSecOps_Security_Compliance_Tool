from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime
from enum import Enum
import hashlib


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class UnifiedFinding:
    finding_id: str
    tool: str
    rule_id: str
    
    title: str
    description: str
    severity: Severity
    
    file_path: str
    line_start: int
    line_end: int
    
    code_snippet: Optional[str] = None
    
    categories: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    owasp_categories: List[str] = field(default_factory=list)
    
    detected_at: datetime = field(default_factory=datetime.now)
    
    raw_data: dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            'finding_id': self.finding_id,
            'tool': self.tool,
            'rule_id': self.rule_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'file_path': self.file_path,
            'line_start': self.line_start,
            'line_end': self.line_end,
            'code_snippet': self.code_snippet,
            'categories': self.categories,
            'cwe_ids': self.cwe_ids,
            'owasp_categories': self.owasp_categories,
            'detected_at': self.detected_at.isoformat(),
        }
    
    @staticmethod
    def generate_id(tool: str, rule_id: str, file_path: str, line: int) -> str:
        unique_string = f"{tool}:{rule_id}:{file_path}:{line}"
        hash_object = hashlib.md5(unique_string.encode())
        return f"{tool}_{hash_object.hexdigest()[:12]}"


if __name__ == "__main__":
    pass