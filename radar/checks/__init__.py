from dataclasses import dataclass
@dataclass
class Finding:
    code: str; severity: str = "low"; reason: str = ""; recommendation: str = ""
