from dataclasses import dataclass
from typing import Protocol
from . import Finding

class CheckContext(Protocol):
    pass

class Check(Protocol):
    def run(self, ctx: CheckContext) -> list[Finding]: ...

ALL_CHECKS = []
