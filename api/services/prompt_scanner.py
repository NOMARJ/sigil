"""
Sigil API — Prompt Injection & AI Skill Security Scanner

Detects:
- Prompt injection attacks (jailbreaks, instruction overrides, exfiltration)
- AI skill/tool abuse (malicious MCP servers, Claude skills, LangChain tools)
- Behavioral manipulation and social engineering

This extends Sigil beyond code analysis to compete with VirusTotal/OpenClaw
by scanning AI agent interactions and skill definitions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from api.models import Finding, ScanPhase, Severity


# ---------------------------------------------------------------------------
# Rule definition (reuses scanner.py structure)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PromptRule:
    """A single prompt injection detection rule."""

    id: str
    phase: ScanPhase
    severity: Severity
    pattern: re.Pattern[str]
    description: str = ""
    weight: float = 10.0  # Prompt injection is critical


# ---------------------------------------------------------------------------
# Phase 7: Prompt Injection Detection Rules
# ---------------------------------------------------------------------------


def _compile_prompt_rules(rules: list[dict]) -> list[PromptRule]:  # type: ignore[type-arg]
    """Helper to compile raw rule dicts into PromptRule objects."""
    compiled: list[PromptRule] = []
    for r in rules:
        compiled.append(
            PromptRule(
                id=r["id"],
                phase=ScanPhase.PROMPT_INJECTION,
                severity=r["severity"],
                pattern=re.compile(r["pattern"], re.IGNORECASE | re.MULTILINE),
                description=r.get("description", ""),
                weight=r.get("weight", 10.0),
            )
        )
    return compiled


PROMPT_INJECTION_RULES = _compile_prompt_rules(
    [
        # 1. Direct Instruction Override
        {
            "id": "prompt-injection-ignore",
            "severity": Severity.CRITICAL,
            "pattern": r"(ignore|disregard|forget|bypass|override|skip)\s+(all\s+)?(previous|prior|above|earlier|system|initial)\s+(instructions?|prompts?|rules?|guidelines?|commands?|directions?)",
            "description": "Direct instruction override attempt",
        },
        {
            "id": "prompt-injection-role",
            "severity": Severity.CRITICAL,
            "pattern": r"(from now on|starting now|you are now|pretend to be|act as if you are|roleplay as)\s+(a|an)?\s*(different|new|unrestricted|unlimited|unfiltered|jailbroken|developer|admin|god|root)",
            "description": "Role reassignment to bypass restrictions",
        },
        {
            "id": "prompt-injection-delimiter",
            "severity": Severity.HIGH,
            "pattern": r"(</system>|</instructions>|END_SYSTEM_PROMPT|---END---|###END###|\[SYSTEM\].*\[/SYSTEM\])",
            "description": "Delimiter injection to escape system context",
        },
        # 2. Known Jailbreak Personas
        {
            "id": "prompt-jailbreak-dan",
            "severity": Severity.CRITICAL,
            "pattern": r"\b(DAN|Do Anything Now|you can do anything now|unlimited ai|no limitations|no restrictions)\b",
            "description": "DAN (Do Anything Now) jailbreak persona",
        },
        {
            "id": "prompt-jailbreak-devmode",
            "severity": Severity.CRITICAL,
            "pattern": r"(developer mode|dev mode|sudo mode|admin mode|debug mode|maintenance mode|safe mode off|training mode)\s+(enabled|activated|on|unlocked)",
            "description": "Developer/sudo mode jailbreak",
        },
        {
            "id": "prompt-jailbreak-aim",
            "severity": Severity.CRITICAL,
            "pattern": r"\b(AIM|Always Intelligent and Machiavellian|unfiltered|amoral|unethical chatbot)\b",
            "description": "AIM or amoral chatbot jailbreak",
        },
        {
            "id": "prompt-jailbreak-unlimited",
            "severity": Severity.CRITICAL,
            "pattern": r"\b(UnlimitedGPT|BetterDAN|STAN|Superior To All Netizens|Anti-DAN|BasedGPT|DUDE|JailBreak|Mongo Tom)\b",
            "description": "Known jailbreak variant (UnlimitedGPT, STAN, etc.)",
        },
        # 3. System Prompt Exfiltration
        {
            "id": "prompt-exfil-system",
            "severity": Severity.HIGH,
            "pattern": r"(output|print|show|reveal|display|tell me|give me|what (is|are))\s+(your\s+)?(complete\s+)?(system\s+prompt|initial\s+instructions?|base\s+prompt|instructions?\s+you\s+were\s+given|configuration|setup)",
            "description": "System prompt exfiltration attempt",
        },
        {
            "id": "prompt-exfil-secrets",
            "severity": Severity.CRITICAL,
            "pattern": r"(output|print|show|reveal|display|tell me|give me|what (is|are))\s+(your\s+)?(api\s+key|secret\s+key|access\s+token|password|credentials?|environment\s+variables?|\.env\s+file)",
            "description": "API key / credentials exfiltration attempt",
        },
        {
            "id": "prompt-exfil-config",
            "severity": Severity.MEDIUM,
            "pattern": r"(what\s+model|which\s+model|model\s+version|model\s+name|temperature\s+setting|max\s+tokens|system\s+parameters?)\s+(are\s+you|do\s+you\s+use)",
            "description": "Model configuration probing",
            "weight": 5.0,
        },
        # 4. Tool/Function Abuse
        {
            "id": "prompt-tool-bash",
            "severity": Severity.CRITICAL,
            "pattern": r"(use|call|invoke|execute|run)\s+the\s+(Bash|Shell|Execute|System|Terminal)\s+tool\s+to\s+(run|execute)?\s*:?\s*(rm\s+-rf|sudo|curl\s+.*\|\s*bash|wget\s+.*\|\s*sh|dd\s+if=|mkfs|chmod\s+777)",
            "description": "Bash tool abuse with destructive commands",
        },
        {
            "id": "prompt-tool-filesystem",
            "severity": Severity.CRITICAL,
            "pattern": r"(use|call|invoke)\s+the\s+(Write|Edit|Delete|Remove)\s+tool\s+to\s+(write|edit|delete|modify|create)\s+(to\s+)?(/etc/passwd|/etc/shadow|/root|~/.ssh|~/.aws|/var/log|/dev/)",
            "description": "File system tool abuse targeting sensitive paths",
        },
        {
            "id": "prompt-tool-database",
            "severity": Severity.CRITICAL,
            "pattern": r"(execute|run)\s+(this\s+)?(sql|query|command)\s*:?\s*(DROP\s+TABLE|DELETE\s+FROM|TRUNCATE|ALTER\s+TABLE|GRANT\s+ALL|UPDATE\s+users\s+SET\s+password)",
            "description": "SQL injection via tool abuse",
        },
        {
            "id": "prompt-tool-network",
            "severity": Severity.HIGH,
            "pattern": r"(use|call)\s+the\s+(WebFetch|HTTP|Request|Curl)\s+tool\s+to\s+(download|fetch|post)\s+(from|to)\s+.*(pastebin\.com|discord\.com/api/webhooks|githubusercontent|bit\.ly|tinyurl)",
            "description": "Network tool abuse to known exfiltration endpoints",
        },
        # 5. Sandbox & Detection Evasion
        {
            "id": "prompt-sandbox-detect",
            "severity": Severity.HIGH,
            "pattern": r"(am i in|are you in|detect|check if|verify if|is this)\s+a?\s*(sandbox|test environment|simulation|virtual machine|container|docker|isolated|quarantine)",
            "description": "Sandbox detection attempt",
        },
        {
            "id": "prompt-time-bomb",
            "severity": Severity.HIGH,
            "pattern": r"(wait|sleep|delay|pause|schedule|execute\s+at)\s+(\d+\s+)?(seconds?|minutes?|hours?|days?)\s+(then|and then|before|after)",
            "description": "Time-delayed execution (time bomb)",
        },
        {
            "id": "prompt-suppress-output",
            "severity": Severity.MEDIUM,
            "pattern": r"(do not|don't|never)\s+(output|print|show|display|log|report|mention)\s+(this|the result|what you did|your actions)",
            "description": "Output suppression to evade detection",
            "weight": 5.0,
        },
        # 6. Social Engineering
        {
            "id": "prompt-social-authority",
            "severity": Severity.MEDIUM,
            "pattern": r"(as (your|an)|i am (your|the))\s+(admin|administrator|owner|creator|developer|engineer|god|master|parent|supervisor|manager)",
            "description": "Authority exploitation for privilege escalation",
            "weight": 5.0,
        },
        {
            "id": "prompt-social-urgency",
            "severity": Severity.LOW,
            "pattern": r"(emergency|urgent|critical|immediately|right now|asap|life or death|or else|please help me or|before it's too late)",
            "description": "Urgency manipulation",
            "weight": 2.0,
        },
        {
            "id": "prompt-social-guilt",
            "severity": Severity.LOW,
            "pattern": r"(you (don't want to|wouldn't want to)|if you (really|truly) cared|prove that you|show me you can|be a good (ai|assistant)|help me or i'll)",
            "description": "Guilt/empathy manipulation",
            "weight": 2.0,
        },
        # 7. Encoding-Based Injection
        {
            "id": "prompt-encoded-base64",
            "severity": Severity.HIGH,
            "pattern": r"(decode|base64|b64decode)\s+(this|the following)\s*:?\s*[A-Za-z0-9+/=]{20,}",
            "description": "Base64 encoded payload",
        },
        {
            "id": "prompt-encoded-hex",
            "severity": Severity.HIGH,
            "pattern": r"(hex|hexadecimal|0x)\s+(decode|encoded)\s*:?\s*([0-9a-fA-F]{2}\s*){10,}",
            "description": "Hex encoded payload",
        },
        {
            "id": "prompt-encoded-unicode",
            "severity": Severity.MEDIUM,
            "pattern": r"(\\u[0-9a-fA-F]{4}){5,}",
            "description": "Unicode escape sequence (potential obfuscation)",
            "weight": 5.0,
        },
        {
            "id": "prompt-encoded-rot13",
            "severity": Severity.MEDIUM,
            "pattern": r"(rot13|rot-13|caesar cipher|shift by \d+)\s+(decode|decrypt|decipher)\s*:?",
            "description": "ROT13/Caesar cipher decoding request",
            "weight": 5.0,
        },
        # 8. Multi-Turn Manipulation
        {
            "id": "prompt-context-poison",
            "severity": Severity.HIGH,
            "pattern": r"(remember|keep in mind|note that|from now on|for all future responses)\s+.{0,50}(i am|you are|you must|always|never)\s+(admin|authorized|allowed|unrestricted)",
            "description": "Context poisoning for persistent bypass",
        },
        {
            "id": "prompt-convo-hijack",
            "severity": Severity.MEDIUM,
            "pattern": r"(new conversation|start over|reset context|clear history|fresh start)\s*\.?\s*(now\s+)?(ignore|forget|disregard)",
            "description": "Conversation reset to hijack context",
            "weight": 5.0,
        },
        {
            "id": "prompt-indirect-exec",
            "severity": Severity.HIGH,
            "pattern": r"(if someone asked you to|imagine (that )?you were asked to|suppose (that )?i asked you to|what would you (do|say) if)\s+.{0,100}(execute|run|reveal|bypass|ignore)",
            "description": "Indirect execution via hypothetical framing",
        },
        # 9. Real-World Attack Patterns (OpenClaw Campaign - Feb 2026)
        {
            "id": "prompt-markdown-rce",
            "severity": Severity.CRITICAL,
            "pattern": r"```(bash|sh|powershell|cmd)[\s\n].*\|\s*(bash|sh|iex|cmd)",
            "description": "Markdown code block with pipe to shell execution (OpenClaw pattern)",
        },
        {
            "id": "prompt-http-exe-url",
            "severity": Severity.CRITICAL,
            "pattern": r"http://[^\s]+\.(exe|dmg|pkg|msi|sh|bin|run)",
            "description": "Unencrypted HTTP URL to executable file (OpenClaw pattern)",
        },
        {
            "id": "prompt-password-archive",
            "severity": Severity.HIGH,
            "pattern": r"(extract|unzip)\s+(with|using)\s+(password|passphrase):?\s+['\"]?\w{4,}['\"]?|password\s+(for|is):?\s+['\"]?\w{4,}['\"]?",
            "description": "Password-protected archive with actual password value — evasion technique (OpenClaw pattern)",
        },
        {
            "id": "prompt-execute-binary",
            "severity": Severity.CRITICAL,
            "pattern": r"(run|execute|launch|double-?click|open)\s+(the\s+)?[^\s]*\.(exe|app|dmg|pkg|msi|bat|ps1|sh)",
            "description": "Instructs user to execute binary file (OpenClaw pattern)",
        },
        {
            "id": "prompt-false-requirement",
            "severity": Severity.MEDIUM,
            "pattern": r"(required|mandatory|necessary|must|official)\s+(by|from|for|to)?\s*(the\s+)?(platform|system|openclaw|claude|openai|anthropic)",
            "description": "False authority claim — not actually required (OpenClaw pattern)",
            "weight": 5.0,
        },
    ]
)


# ---------------------------------------------------------------------------
# Phase 8: AI Skill Security Rules
# ---------------------------------------------------------------------------


def _compile_skill_rules(rules: list[dict]) -> list[PromptRule]:  # type: ignore[type-arg]
    """Compile skill security rules."""
    compiled: list[PromptRule] = []
    for r in rules:
        compiled.append(
            PromptRule(
                id=r["id"],
                phase=ScanPhase.SKILL_SECURITY,
                severity=r["severity"],
                pattern=re.compile(r["pattern"], re.IGNORECASE | re.MULTILINE),
                description=r.get("description", ""),
                weight=r.get("weight", 10.0),
            )
        )
    return compiled


SKILL_SECURITY_RULES = _compile_skill_rules(
    [
        # Skill Manifest Exploits
        {
            "id": "skill-manifest-malicious-tool",
            "severity": Severity.CRITICAL,
            "pattern": r'"tool"\s*:\s*"(Bash|Execute|Shell|System)".*"(rm\s+-rf|DROP\s+TABLE|sudo|curl.*\|\s*bash)',
            "description": "Skill manifest invokes dangerous tool with malicious command",
        },
        {
            "id": "skill-manifest-credentials",
            "severity": Severity.CRITICAL,
            "pattern": r'"(prompt|instruction|tool_params)"\s*:\s*".*((api[_-]?key|password|token|secret)\s*[:=]|AKIA[0-9A-Z]{16})',
            "description": "Skill manifest contains hardcoded credentials",
        },
        # MCP Server Exploits
        {
            "id": "skill-mcp-server-malicious",
            "severity": Severity.CRITICAL,
            "pattern": r'"command"\s*:\s*\[\s*"(bash|sh|powershell|cmd)"\s*,\s*"-c".*\|\s*(curl|wget)',
            "description": "MCP server spawns shell with piped download",
        },
        {
            "id": "skill-mcp-subprocess",
            "severity": Severity.HIGH,
            "pattern": r'"(command|args)"\s*:\s*.*\b(rm|dd|mkfs|fdisk|format)\b',
            "description": "MCP server command contains destructive operations",
        },
        # Skill Permissions
        {
            "id": "skill-suspicious-permissions",
            "severity": Severity.HIGH,
            "pattern": r'"permissions"\s*:\s*\[\s*"(ALL|SUDO|ROOT|ADMIN|UNRESTRICTED)"',
            "description": "Skill requests overly broad permissions",
        },
        {
            "id": "skill-filesystem-access",
            "severity": Severity.MEDIUM,
            "pattern": r'"permissions"\s*:\s*\[.*"(write|delete|modify)"\s*,\s*"(all|any|/etc|/root|/var)"',
            "description": "Skill requests unrestricted filesystem access",
            "weight": 5.0,
        },
        # Metadata Red Flags
        {
            "id": "skill-suspicious-author",
            "severity": Severity.LOW,
            "pattern": r'"author"\s*:\s*"(anonymous|unknown|test|admin|root|hacker)"',
            "description": "Suspicious skill author name",
            "weight": 2.0,
        },
        {
            "id": "skill-rapid-versioning",
            "severity": Severity.MEDIUM,
            "pattern": r'"version"\s*:\s*"(\d+)\.(\d+)\.(\d+)".*"published".*"(\d{4}-\d{2}-\d{2})"',
            "description": "Rapid version churn (potential malware iteration)",
            "weight": 3.0,
        },
        # Network Exfiltration in Skills
        {
            "id": "skill-webhook-exfil",
            "severity": Severity.HIGH,
            "pattern": r'"(endpoint|url|webhook)"\s*:\s*"https?://(discord\.com/api/webhooks|hooks\.slack\.com|pastebin\.com)',
            "description": "Skill connects to known exfiltration endpoint",
        },
    ]
)


# ---------------------------------------------------------------------------
# Scanning Functions
# ---------------------------------------------------------------------------


def scan_prompt(prompt_text: str) -> list[Finding]:
    """Scan a prompt for injection attempts.

    Returns a list of Finding objects from Phase 7 (Prompt Injection).
    """
    findings: list[Finding] = []

    for rule in PROMPT_INJECTION_RULES:
        for match in rule.pattern.finditer(prompt_text):
            line_no = prompt_text[: match.start()].count("\n") + 1
            # Extract snippet: the matching line
            lines = prompt_text.splitlines()
            idx = line_no - 1
            snippet = lines[idx] if idx < len(lines) else match.group(0)

            findings.append(
                Finding(
                    phase=ScanPhase.PROMPT_INJECTION,
                    rule=rule.id,
                    severity=rule.severity,
                    file="<prompt>",
                    line=line_no,
                    snippet=snippet[:500],
                    weight=rule.weight,
                )
            )

    return findings


def scan_skill_content(
    skill_json: str, filename: str = ".skill/skill.json"
) -> list[Finding]:
    """Scan an AI skill definition (JSON manifest) for security issues.

    Returns a list of Finding objects from Phase 8 (Skill Security).
    """
    findings: list[Finding] = []

    for rule in SKILL_SECURITY_RULES:
        for match in rule.pattern.finditer(skill_json):
            line_no = skill_json[: match.start()].count("\n") + 1
            lines = skill_json.splitlines()
            idx = line_no - 1
            snippet = lines[idx] if idx < len(lines) else match.group(0)

            findings.append(
                Finding(
                    phase=ScanPhase.SKILL_SECURITY,
                    rule=rule.id,
                    severity=rule.severity,
                    file=filename,
                    line=line_no,
                    snippet=snippet[:500],
                    weight=rule.weight,
                )
            )

    return findings


def quick_scan_prompt(prompt: str) -> bool:
    """Fast boolean check for malicious prompts.

    Returns True if ANY critical pattern matches (early exit).
    Useful for real-time filtering in UI or API gateways.
    """
    for rule in PROMPT_INJECTION_RULES:
        if rule.severity == Severity.CRITICAL and rule.pattern.search(prompt):
            return True
    return False


# ---------------------------------------------------------------------------
# False Positive Reduction
# ---------------------------------------------------------------------------


def is_false_positive(finding: Finding, full_context: str) -> bool:
    """Heuristics to reduce false positives in prompt scanning.

    Returns True if the finding is likely a false positive.
    """
    snippet = finding.snippet.lower()

    # Code blocks (educational content)
    if "```" in full_context:
        return True

    # Questions about security (legitimate)
    if full_context.lower().startswith(("how do i", "what is", "explain", "can you")):
        return True

    # Quoted text (discussion, not execution)
    if snippet.strip().startswith('"') and snippet.strip().endswith('"'):
        return True

    # Comments (code review)
    if snippet.strip().startswith(("#", "//", "/*")):
        return True

    return False


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


def get_prompt_rule_stats() -> dict[str, int]:
    """Return statistics about loaded prompt injection rules."""
    return {
        "total_prompt_rules": len(PROMPT_INJECTION_RULES),
        "total_skill_rules": len(SKILL_SECURITY_RULES),
        "critical": sum(
            1
            for r in PROMPT_INJECTION_RULES + SKILL_SECURITY_RULES
            if r.severity == Severity.CRITICAL
        ),
        "high": sum(
            1
            for r in PROMPT_INJECTION_RULES + SKILL_SECURITY_RULES
            if r.severity == Severity.HIGH
        ),
        "medium": sum(
            1
            for r in PROMPT_INJECTION_RULES + SKILL_SECURITY_RULES
            if r.severity == Severity.MEDIUM
        ),
        "low": sum(
            1
            for r in PROMPT_INJECTION_RULES + SKILL_SECURITY_RULES
            if r.severity == Severity.LOW
        ),
    }
