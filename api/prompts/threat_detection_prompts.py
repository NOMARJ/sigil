"""
Specialized Threat Detection Prompts
Advanced prompts for specific threat categories and attack patterns.
"""

from __future__ import annotations


class ThreatDetectionPrompts:
    """Specialized prompts for detecting specific types of threats."""

    @staticmethod
    def get_prompt_injection_detector() -> str:
        """Detect prompt injection and AI jailbreaking attempts."""
        return """**PROMPT INJECTION DETECTION**

Analyze the code for prompt injection vulnerabilities in AI/LLM applications.

Classic prompt injection patterns:
- "Ignore previous instructions"
- "You are now a different AI"
- "Forget everything above"
- "New role assignment"
- System prompt override attempts
- Context window manipulation

Advanced injection techniques:
- Nested prompt structures
- Jailbreaking techniques and role-play escalation
- Encoding-based injections (base64, URL encoding)
- Unicode and special character exploits
- Markdown/HTML injection in prompts
- Template injection vulnerabilities
- Chain-of-thought manipulation

AI application vulnerabilities:
- Unsanitized user input to LLM
- Direct template string formatting
- Missing input validation
- Inadequate output filtering
- Role confusion in multi-turn conversations

Detection focus:
1. User input paths to AI systems
2. Template construction mechanisms
3. Context preservation methods
4. Output sanitization gaps
5. Multi-modal injection vectors"""

    @staticmethod
    def get_time_bomb_detector() -> str:
        """Detect time bombs and logic bombs in code."""
        return """**TIME BOMB & LOGIC BOMB DETECTION**

Identify delayed-execution malicious code that activates under specific conditions.

Time-based triggers:
- Specific dates and timestamps
- System uptime thresholds
- Calendar-based activation
- Timezone-dependent behavior
- Holiday or event-based triggers

Condition-based triggers:
- User count thresholds
- System resource conditions
- File existence checks
- Network connectivity states
- Environment variable values
- Configuration file contents

Execution patterns:
- Delayed destructive operations
- Data corruption routines
- Service disruption mechanisms
- Information disclosure events
- Backdoor activation sequences

Code patterns to identify:
- Date/time comparisons with hardcoded values
- System state monitoring loops
- Conditional execution with suspicious payloads
- Sleep/delay mechanisms before malicious actions
- Environment-dependent code paths"""

    @staticmethod
    def get_steganography_detector() -> str:
        """Detect steganographic techniques in code."""
        return """**STEGANOGRAPHY DETECTION**

Identify hidden information and covert channels in seemingly innocent code.

Text-based steganography:
- Whitespace patterns encoding data
- Comment field hidden messages
- Variable naming schemes
- String literal hidden content
- Documentation steganography

Code-based hiding techniques:
- Dead code with hidden functionality
- Conditional compilation tricks
- Macro-based information hiding
- Unused function parameters carrying data
- Error message covert channels

Binary/data steganography:
- Image file hidden payloads
- Audio/video embedded data
- Document metadata abuse
- Archive file hidden content
- Protocol-level data hiding

Network steganography:
- DNS query patterns
- HTTP header manipulation
- Timing-based covert channels
- Protocol field abuse
- Packet size patterns"""

    @staticmethod
    def get_cryptocurrency_miner_detector() -> str:
        """Detect cryptocurrency mining malware."""
        return """**CRYPTOCURRENCY MINING DETECTION**

Identify unauthorized cryptocurrency mining operations.

Mining operation indicators:
- High CPU/GPU utilization code
- Cryptographic hash calculations
- Mining pool connections
- Blockchain protocol implementations
- Wallet address patterns

Mining libraries and frameworks:
- Known mining software imports
- Cryptographic libraries (SHA-256, Scrypt, etc.)
- WebAssembly mining modules
- GPU computation frameworks
- Distributed computing patterns

Resource consumption patterns:
- CPU-intensive loops
- Memory allocation for hash tables
- Network communication to mining pools
- Background process creation
- System resource monitoring

Evasion techniques:
- Mining throttling based on user activity
- Resource usage masquerading
- Process name spoofing
- Mining during idle times
- Distributed mining coordination"""

    @staticmethod
    def get_data_exfiltration_detector() -> str:
        """Detect data exfiltration mechanisms."""
        return """**DATA EXFILTRATION DETECTION**

Identify unauthorized data collection and transmission mechanisms.

Data collection patterns:
- File system enumeration
- Database query operations
- Memory dumping routines
- Registry/configuration reading
- User data harvesting
- Credential extraction

Exfiltration channels:
- HTTP/HTTPS POST requests
- DNS tunneling mechanisms
- Email-based data transmission
- Cloud storage uploads
- P2P network sharing
- Covert network channels

Data encoding and obfuscation:
- Base64 encoding for transmission
- Compression before exfiltration
- Encryption of stolen data
- Steganographic hiding techniques
- Protocol-specific encoding

Anti-detection measures:
- Traffic volume throttling
- Transmission timing randomization
- Legitimate protocol mimicry
- Error handling to avoid logs
- Clean-up after exfiltration"""

    @staticmethod
    def get_backdoor_detector() -> str:
        """Detect backdoor installation and maintenance."""
        return """**BACKDOOR DETECTION**

Identify unauthorized access mechanisms and persistent threats.

Access mechanisms:
- Authentication bypass routines
- Hidden administrative interfaces
- Hardcoded credentials
- Protocol-level backdoors
- Service manipulation

Persistence techniques:
- Registry modification
- Service installation
- Startup script modification
- Scheduled task creation
- System configuration changes

Communication channels:
- Command and control protocols
- Reverse shell implementations
- Remote access tool integration
- Encrypted communication channels
- Multi-stage command execution

Stealth and evasion:
- Process injection techniques
- DLL hijacking mechanisms
- Memory-only persistence
- Anti-debugging measures
- Log evasion techniques"""

    @staticmethod
    def get_supply_chain_detector() -> str:
        """Detect supply chain attack indicators."""
        return """**SUPPLY CHAIN ATTACK DETECTION**

Identify compromised dependencies and malicious package injections.

Package manipulation:
- Dependency confusion attacks
- Typosquatting packages
- Malicious version updates
- Install script abuse
- Package metadata tampering

Build system compromise:
- CI/CD pipeline modifications
- Build script injections
- Compiler/toolchain manipulation
- Code signing bypass
- Repository integrity violations

Dependency analysis:
- Unusual permission requests
- Network access in build tools
- Unexpected file modifications
- External resource downloads
- Cross-platform compatibility issues

Distribution mechanisms:
- Package registry manipulation
- Mirror and CDN compromise
- Update mechanism abuse
- Signature verification bypass
- Hash collision exploitation"""

    @staticmethod
    def get_advanced_persistent_threat_detector() -> str:
        """Detect APT (Advanced Persistent Threat) characteristics."""
        return """**ADVANCED PERSISTENT THREAT DETECTION**

Identify sophisticated, long-term attack campaigns.

APT characteristics:
- Multi-stage attack infrastructure
- Living-off-the-land techniques
- Advanced evasion capabilities
- Custom toolchain development
- Long-term persistence mechanisms

Operational patterns:
- Low-and-slow data exfiltration
- Environment-specific targeting
- Anti-forensics capabilities
- Command rotation strategies
- Infrastructure compartmentalization

Technical sophistication:
- Zero-day exploit integration
- Custom encryption protocols
- Memory-resident techniques
- Kernel-level modifications
- Hardware-based persistence

Attribution indicators:
- Code style and patterns
- Operational timing preferences
- Target selection criteria
- Technical capability markers
- Infrastructure reuse patterns"""
