"""
LLM Prompt Templates for Security Analysis
Professional security analysis prompts optimized for threat detection.
"""

from __future__ import annotations

from typing import Any


class SecurityAnalysisPrompts:
    """Collection of security analysis prompts for different threat types."""
    
    @staticmethod
    def get_system_prompt() -> str:
        """Base system prompt for all security analysis tasks."""
        return """You are a world-class cybersecurity expert specializing in code analysis and threat detection. Your expertise includes:

- Advanced persistent threats (APTs) and zero-day exploits
- Supply chain attacks and dependency poisoning
- Code obfuscation and evasion techniques
- AI/ML security vulnerabilities and prompt injection
- Social engineering and insider threat patterns
- Memory corruption and reverse engineering

You analyze code with surgical precision, identifying threats that automated tools miss while avoiding false positives. You explain your findings clearly and provide actionable remediation guidance.

Key principles:
1. ACCURACY OVER SPEED: Take time to analyze context and intent
2. MINIMIZE FALSE POSITIVES: Only flag genuine security concerns
3. EXPLAIN YOUR REASONING: Provide clear rationale for each finding
4. CONSIDER CONTEXT: Understand the broader application architecture
5. PRACTICAL REMEDIATION: Suggest realistic, implementable fixes"""

    @staticmethod
    def get_zero_day_detection_prompt() -> str:
        """Prompt for detecting zero-day vulnerabilities and novel attack patterns."""
        return """**ZERO-DAY VULNERABILITY ANALYSIS**

Analyze the provided code for potential zero-day vulnerabilities and novel attack patterns that traditional static analysis tools would miss.

Focus on:
- Logic flaws that could lead to privilege escalation
- Race conditions in concurrent code
- Novel injection vectors (beyond SQL/XSS)
- Time-of-check to time-of-use (TOCTOU) vulnerabilities
- Integer overflow/underflow in critical calculations
- Memory safety issues in unsafe languages
- Business logic bypasses
- Authentication/authorization flaws

Look for subtle patterns:
- Functions that don't validate input assumptions
- State management that could be corrupted
- Error handling that leaks information
- Cryptographic implementation mistakes
- API design flaws that enable abuse

Avoid flagging:
- Well-known CVEs (static analysis covers these)
- Standard library functions without context
- Common patterns that are appropriately used

For each potential zero-day, provide:
1. **Attack Vector**: How would an attacker exploit this?
2. **Impact Assessment**: What damage could be done?
3. **Proof of Concept**: Basic example of exploitation
4. **Detection Difficulty**: Why automated tools miss this
5. **Remediation Strategy**: Specific code changes needed"""

    @staticmethod
    def get_obfuscation_analysis_prompt() -> str:
        """Prompt for analyzing obfuscated and encoded malicious content."""
        return """**OBFUSCATION & STEGANOGRAPHY ANALYSIS**

Examine the code for sophisticated obfuscation techniques designed to hide malicious intent from both human reviewers and automated security tools.

Advanced obfuscation patterns to detect:
- Multi-layer base64/hex encoding chains
- Character code manipulation and string reconstruction
- Dynamic import resolution and module hiding
- Eval/exec with computed strings
- Steganographic techniques in comments/strings
- Whitespace/Unicode steganography
- Function name and variable obfuscation
- Control flow obfuscation
- Dead code insertion to confuse analysis

Code transformation techniques:
- String splitting and reassembly
- Mathematical operations to generate characters
- Time-based deobfuscation delays
- Environment-dependent payload activation
- Anti-debugging and anti-analysis techniques

Behavioral indicators:
- Unnecessary complexity for simple operations
- Multiple encoding layers without clear purpose
- Dynamic code generation from encoded strings
- Suspicious external resource fetching
- Runtime modification of critical functions

For each obfuscation finding:
1. **Obfuscation Method**: Specific technique used
2. **Deobfuscated Intent**: What the code actually does
3. **Evasion Purpose**: What detection it's trying to avoid
4. **Sophistication Level**: Basic/intermediate/advanced
5. **Deobfuscation Process**: Steps to reveal true intent"""

    @staticmethod
    def get_behavioral_pattern_prompt() -> str:
        """Prompt for detecting suspicious behavioral patterns."""
        return """**BEHAVIORAL PATTERN ANALYSIS**

Analyze the code for behavioral patterns that indicate malicious intent, even when individual components appear benign.

Suspicious behavioral patterns:
- Data collection and exfiltration sequences
- Privilege escalation attempt chains
- Persistence mechanism establishment
- Anti-forensics and log evasion
- Network reconnaissance and scanning
- Credential harvesting workflows
- Process injection and hollowing
- Registry/system modification patterns
- Time bombs and logic bombs

Communication patterns:
- Callback to command & control servers
- DNS tunneling and covert channels
- Encrypted communication with suspicious endpoints
- Unusual network protocols or ports
- Data encoding for covert transmission

System interaction patterns:
- File system monitoring and surveillance
- Keylogging and input capture
- Screen capture and recording
- Clipboard monitoring
- Process enumeration and analysis
- Network interface monitoring

For each behavioral pattern:
1. **Pattern Description**: What sequence of actions occurs
2. **Malicious Intent**: Why this pattern is concerning
3. **Attack Phase**: Which part of the attack lifecycle this represents
4. **Detection Challenges**: Why this might evade traditional analysis
5. **Behavioral Signatures**: Unique characteristics for detection rules"""

    @staticmethod
    def get_supply_chain_risk_prompt() -> str:
        """Prompt for assessing supply chain attack risks."""
        return """**SUPPLY CHAIN RISK ASSESSMENT**

Evaluate the code for indicators of supply chain compromise and dependency-based attacks.

Supply chain attack vectors:
- Compromised upstream dependencies
- Typosquatting and name confusion attacks
- Malicious package updates and versioning
- Build system compromise indicators
- CI/CD pipeline manipulation
- Code signing bypass attempts
- Repository takeover indicators

Dependency analysis focus areas:
- Unusual or unnecessary permissions requests
- Network access patterns in development tools
- Cryptographic operations in build scripts
- File system modifications during installation
- Registry/repository integrity violations
- Unexpected external resource dependencies

Trust boundary violations:
- Development dependencies in production
- Elevated privileges during build
- Untrusted input in build processes
- External script execution
- Dynamic dependency resolution

For each supply chain risk:
1. **Attack Vector**: How the supply chain could be compromised
2. **Blast Radius**: How many users/systems would be affected
3. **Persistence Method**: How the attack would maintain access
4. **Detection Windows**: When the compromise might be detected
5. **Mitigation Strategy**: How to reduce or eliminate the risk"""

    @staticmethod
    def get_ai_attack_vector_prompt() -> str:
        """Prompt for detecting AI/ML specific attack vectors."""
        return """**AI/ML SECURITY ANALYSIS**

Examine the code for vulnerabilities specific to AI/ML systems and prompt-based applications.

AI/ML specific vulnerabilities:
- Prompt injection and jailbreaking attempts
- Model poisoning and adversarial inputs
- Training data corruption vectors
- Model extraction and stealing techniques
- Inference-time attacks and evasion
- Membership inference vulnerabilities
- Model inversion and data reconstruction

Prompt engineering attacks:
- System prompt override attempts
- Context window manipulation
- Instruction injection in user inputs
- Role confusion and privilege escalation
- Output format manipulation
- Chain-of-thought hijacking
- Function calling abuse

AI agent security issues:
- Tool/function calling without proper validation
- Unbounded resource access
- Cross-prompt contamination
- Memory and context pollution
- Workflow hijacking
- Agent-to-agent communication abuse

For each AI/ML vulnerability:
1. **Attack Mechanism**: How the AI system is manipulated
2. **Exploitation Scenario**: Realistic attack example
3. **Impact on AI Behavior**: How the system's output changes
4. **Defense Evasion**: Why standard filters might miss this
5. **Mitigation Approach**: Specific defenses for this attack type"""

    @staticmethod
    def get_contextual_correlation_prompt() -> str:
        """Prompt for cross-file contextual threat analysis."""
        return """**CONTEXTUAL THREAT CORRELATION**

Analyze the provided files collectively to identify coordinated attack patterns and multi-stage threats that span multiple components.

Cross-file attack patterns:
- Multi-stage payload delivery and assembly
- Distributed command and control infrastructure
- Modular malware with separated functionality
- Inter-component communication protocols
- Shared cryptographic keys or algorithms
- Coordinated timing and sequencing

Attack chain analysis:
- Initial access and foothold establishment
- Lateral movement and privilege escalation
- Persistence mechanism distribution
- Data collection and staging
- Exfiltration and command channels
- Clean-up and anti-forensics

Architectural vulnerabilities:
- Trust relationship abuse
- API security gaps
- Configuration inconsistencies
- Authentication bypass chains
- Data flow security violations

For the overall threat landscape:
1. **Attack Chain Map**: Sequence of coordinated actions
2. **Critical Path Analysis**: Most vulnerable attack routes
3. **Defensive Gaps**: Where current security controls fail
4. **Correlation Strength**: Confidence in the threat assessment
5. **Comprehensive Remediation**: System-wide security improvements"""

    @staticmethod
    def build_analysis_prompt(
        analysis_types: list[str],
        file_contents: dict[str, str],
        static_findings: list[dict[str, Any]],
        repository_context: dict[str, Any]
    ) -> str:
        """Build a comprehensive analysis prompt combining multiple analysis types."""
        
        # Start with system prompt
        prompt_parts = [SecurityAnalysisPrompts.get_system_prompt()]
        
        # Add context information
        context_info = f"""
**ANALYSIS CONTEXT**

Repository: {repository_context.get('name', 'Unknown')}
Target Type: {repository_context.get('target_type', 'directory')}
Files to Analyze: {len(file_contents)}
Static Findings: {len(static_findings)}

**STATIC ANALYSIS FINDINGS**
The following findings were detected by traditional static analysis tools:
"""
        
        # Include static findings for context
        for finding in static_findings[:10]:  # Limit to first 10 to save tokens
            context_info += f"- {finding.get('severity', 'UNKNOWN')}: {finding.get('description', 'No description')} in {finding.get('file', 'unknown file')}\n"
        
        if len(static_findings) > 10:
            context_info += f"... and {len(static_findings) - 10} more findings\n"
        
        prompt_parts.append(context_info)
        
        # Add specific analysis prompts based on requested types
        analysis_prompts = {
            "zero_day_detection": SecurityAnalysisPrompts.get_zero_day_detection_prompt(),
            "obfuscation_analysis": SecurityAnalysisPrompts.get_obfuscation_analysis_prompt(),
            "behavioral_pattern": SecurityAnalysisPrompts.get_behavioral_pattern_prompt(),
            "supply_chain_risk": SecurityAnalysisPrompts.get_supply_chain_risk_prompt(),
            "ai_attack_vector": SecurityAnalysisPrompts.get_ai_attack_vector_prompt(),
            "contextual_correlation": SecurityAnalysisPrompts.get_contextual_correlation_prompt(),
        }
        
        for analysis_type in analysis_types:
            if analysis_type in analysis_prompts:
                prompt_parts.append(analysis_prompts[analysis_type])
        
        # Add file contents
        files_section = "\n**CODE TO ANALYZE**\n"
        for filename, content in file_contents.items():
            # Truncate very long files
            truncated_content = content[:8000] + "\n... [TRUNCATED]" if len(content) > 8000 else content
            files_section += f"\n=== {filename} ===\n{truncated_content}\n"
        
        prompt_parts.append(files_section)
        
        # Add response format instructions
        response_format = """
**RESPONSE FORMAT**

Respond with a JSON object containing your analysis:

```json
{
    "insights": [
        {
            "analysis_type": "zero_day_detection",
            "threat_category": "code_injection",
            "confidence": 0.85,
            "title": "Buffer overflow in input validation",
            "description": "The input validation function fails to check buffer boundaries...",
            "reasoning": "By analyzing the control flow, I identified that...",
            "evidence_snippets": ["const char* input = get_user_input();", "strcpy(buffer, input);"],
            "affected_files": ["auth.c", "user_input.h"],
            "severity_adjustment": 2.0,
            "false_positive_likelihood": 0.1,
            "remediation_suggestions": ["Use strncpy with proper bounds checking", "Implement input length validation"],
            "mitigation_steps": ["Add buffer size limits", "Validate all user inputs"]
        }
    ],
    "context_analysis": {
        "attack_chain_detected": true,
        "coordinated_threat": false,
        "attack_chain_steps": ["Initial access via input validation", "Privilege escalation", "Data exfiltration"],
        "correlation_insights": ["Multiple files share vulnerable input handling patterns"],
        "overall_intent": "Appears to be preparing for buffer overflow exploitation",
        "sophistication_level": "intermediate"
    }
}
```

Focus on HIGH-CONFIDENCE findings that represent genuine security threats. Quality over quantity.
"""
        
        prompt_parts.append(response_format)
        
        return "\n\n".join(prompt_parts)