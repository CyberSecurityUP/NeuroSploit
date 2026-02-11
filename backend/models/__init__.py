from backend.models.scan import Scan
from backend.models.target import Target
from backend.models.prompt import Prompt
from backend.models.endpoint import Endpoint
from backend.models.vulnerability import Vulnerability, VulnerabilityTest
from backend.models.report import Report
from backend.models.agent_task import AgentTask
from backend.models.vuln_lab import VulnLabChallenge

__all__ = [
    "Scan",
    "Target",
    "Prompt",
    "Endpoint",
    "Vulnerability",
    "VulnerabilityTest",
    "Report",
    "AgentTask",
    "VulnLabChallenge"
]
