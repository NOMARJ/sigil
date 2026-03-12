# LLM Enhancement Plan: Credits System & Interactive Analysis

## Executive Summary

Transform Sigil Pro's LLM feature from a passive scanner to an interactive security assistant with credit-based usage management and Claude Haiku for cost optimization.

## 1. Claude Haiku vs OpenAI Cost Analysis

### Claude 3 Haiku (Recommended)
- **Input**: $0.25/M tokens ($0.00025/1K)
- **Output**: $1.25/M tokens ($0.00125/1K)
- **Speed**: 100+ tokens/sec (3x faster than GPT-4)
- **Quality**: Excellent for code analysis, security patterns
- **8K token scan cost**: ~$0.002-0.004 (15x cheaper than GPT-4)

### GPT-4 Turbo
- **Input**: $10/M tokens ($0.01/1K)
- **Output**: $30/M tokens ($0.03/1K)
- **Speed**: 30-50 tokens/sec
- **Quality**: Superior reasoning but overkill for most security scans
- **8K token scan cost**: ~$0.03-0.06

### GPT-3.5 Turbo
- **Input**: $0.50/M tokens
- **Output**: $1.50/M tokens
- **8K token scan cost**: ~$0.004-0.008
- **Quality**: Inconsistent for security analysis

### Recommendation: Claude Haiku
- **15x cheaper** than GPT-4 for equivalent quality
- **3x faster** response times
- **Better for code**: Trained on more recent codebases
- **Anthropic alignment**: Better at refusing malicious requests

## 2. Credit-Based Token Management System

### Credit Model (Windsurf-Style)

```python
# Credit conversion rates
CREDIT_RATES = {
    "claude-3-haiku": 1,      # 1 credit = 1K tokens
    "claude-3-sonnet": 10,     # Premium model
    "claude-3-opus": 40,       # Ultra premium
    "gpt-3.5-turbo": 2,
    "gpt-4-turbo": 20,
}

# Subscription tiers
MONTHLY_CREDITS = {
    "anonymous": 0,      # No LLM access
    "free": 50,         # ~50 basic scans (logged in only)
    "pro": 5000,        # ~5000 scans or 500 deep-dives
    "elite": 15000,     # Elite tier (was Pro+)
    "team": 50000,      # Shared pool
    "enterprise": -1,   # Unlimited
}

# Feature costs
SCAN_COSTS = {
    "quick_scan": 8,          # 8K tokens basic
    "deep_analysis": 32,      # 32K comprehensive
    "interactive_session": 2,  # Per exchange
    "bulk_scan": 100,         # Repository-wide
}
```

### Database Schema (MSSQL)

```sql
-- Credit tracking table
CREATE TABLE user_credits (
    user_id NVARCHAR(128) PRIMARY KEY,
    credits_balance INT DEFAULT 0,
    credits_used_month INT DEFAULT 0,
    bonus_credits INT DEFAULT 0,
    reset_date DATETIME2,
    created_at DATETIME2 DEFAULT GETDATE(),
    CONSTRAINT FK_user_credits_users FOREIGN KEY (user_id) 
        REFERENCES users(id)
);

-- Credit transactions
CREATE TABLE credit_transactions (
    transaction_id UNIQUEIDENTIFIER DEFAULT NEWID() PRIMARY KEY,
    user_id NVARCHAR(128),
    credits_amount INT,
    transaction_type NVARCHAR(50), -- 'scan', 'interactive', 'refund', 'bonus'
    scan_id NVARCHAR(64),
    model_used NVARCHAR(50),
    tokens_used INT,
    created_at DATETIME2 DEFAULT GETDATE(),
    CONSTRAINT FK_transactions_user FOREIGN KEY (user_id) 
        REFERENCES users(id)
);

-- Stored procedures
CREATE PROCEDURE sp_DeductCredits
    @UserId NVARCHAR(128),
    @Amount INT,
    @TransactionType NVARCHAR(50),
    @ScanId NVARCHAR(64) = NULL
AS
BEGIN
    -- Check balance
    IF (SELECT credits_balance FROM user_credits WHERE user_id = @UserId) < @Amount
        RETURN -1; -- Insufficient credits
    
    -- Deduct credits
    UPDATE user_credits 
    SET credits_balance = credits_balance - @Amount,
        credits_used_month = credits_used_month + @Amount
    WHERE user_id = @UserId;
    
    -- Log transaction
    INSERT INTO credit_transactions (user_id, credits_amount, transaction_type, scan_id)
    VALUES (@UserId, -@Amount, @TransactionType, @ScanId);
    
    RETURN 0; -- Success
END;
```

## 3. Interactive Deep-Dive Feature

### Concept: Cherry-Pick & Investigate

Instead of one-shot analysis, allow users to:
1. Get initial scan with findings
2. **Interactively explore** specific threats
3. Request deeper analysis on suspected false positives
4. Get remediation code suggestions
5. Ask follow-up questions

### UI/UX Flow

```typescript
// Interactive session state
interface InteractiveSession {
  sessionId: string;
  scanId: string;
  findings: Finding[];
  selectedFinding: Finding | null;
  conversation: Message[];
  creditsUsed: number;
  context: {
    fileContents: Map<string, string>;
    dependencies: string[];
    gitHistory?: CommitInfo[];
  };
}

// User actions
type UserAction = 
  | { type: "INVESTIGATE_FINDING"; findingId: string }
  | { type: "CHECK_FALSE_POSITIVE"; findingId: string }
  | { type: "GET_REMEDIATION"; findingId: string }
  | { type: "ASK_QUESTION"; question: string }
  | { type: "EXPAND_CONTEXT"; files: string[] }
  | { type: "COMPARE_VERSIONS"; commitA: string; commitB: string };
```

### API Endpoints

```python
@router.post("/scan/{scan_id}/interactive")
async def start_interactive_session(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> InteractiveSessionResponse:
    """Start an interactive analysis session for a scan."""
    # Check credits
    if not await credit_service.has_credits(current_user.id, 2):
        raise HTTPException(402, "Insufficient credits")
    
    # Load scan context
    scan = await db.get_scan(scan_id)
    session = await llm_service.create_interactive_session(
        scan=scan,
        user_id=current_user.id
    )
    
    return InteractiveSessionResponse(
        session_id=session.id,
        findings=scan.findings,
        credits_remaining=await credit_service.get_balance(current_user.id),
        available_actions=["investigate", "false_positive", "remediate", "ask"]
    )

@router.post("/interactive/{session_id}/investigate")
async def investigate_finding(
    session_id: str,
    finding_id: str,
    depth: Literal["quick", "thorough", "exhaustive"] = "quick",
    current_user: User = Depends(get_current_user),
) -> InvestigationResponse:
    """Deep-dive into a specific finding."""
    
    # Credit costs based on depth
    DEPTH_COSTS = {"quick": 2, "thorough": 8, "exhaustive": 20}
    cost = DEPTH_COSTS[depth]
    
    # Deduct credits
    await credit_service.deduct_credits(
        user_id=current_user.id,
        amount=cost,
        transaction_type="investigate",
        scan_id=session_id
    )
    
    # Perform targeted analysis with Claude Haiku
    analysis = await llm_service.investigate_finding(
        session_id=session_id,
        finding_id=finding_id,
        depth=depth,
        model="claude-3-haiku-20240307"  # Fast & cheap
    )
    
    return InvestigationResponse(
        finding_id=finding_id,
        is_false_positive=analysis.false_positive_confidence > 0.7,
        confidence=analysis.confidence,
        evidence=analysis.evidence,
        explanation=analysis.detailed_explanation,
        related_patterns=analysis.similar_patterns,
        credits_used=cost,
        credits_remaining=await credit_service.get_balance(current_user.id)
    )

@router.post("/interactive/{session_id}/ask")
async def ask_question(
    session_id: str,
    question: str,
    include_context: bool = True,
    current_user: User = Depends(get_current_user),
) -> ChatResponse:
    """Ask a follow-up question about the scan."""
    
    # Deduct 2 credits per question
    await credit_service.deduct_credits(
        user_id=current_user.id,
        amount=2,
        transaction_type="interactive_chat"
    )
    
    # Stream response
    response_stream = await llm_service.chat_about_scan(
        session_id=session_id,
        question=question,
        include_context=include_context,
        model="claude-3-haiku-20240307"
    )
    
    return ChatResponse(
        answer=response_stream,
        credits_used=2,
        suggested_followups=["Check dependencies", "Review git history", "Get fix"]
    )
```

### Interactive Features

#### 1. False Positive Analysis
```python
# User selects a finding they think is wrong
finding = "Eval usage in safe context"

# System prompts Haiku with context
prompt = f"""
The user believes this is a false positive:
{finding}

Context:
- File: {file_path}
- Code: {code_snippet}
- Surrounding functions: {context}

Analyze if this is actually safe and explain why/why not.
Consider: input sanitization, execution context, data flow.
"""

# Response explains with confidence score
response = {
    "is_false_positive": True,
    "confidence": 0.85,
    "reasoning": "The eval() is only executed on hardcoded strings...",
    "recommendation": "Add explicit whitelist anyway for defense-in-depth"
}
```

#### 2. Remediation Suggestions
```python
# User wants fix for a finding
finding = "SQL injection vulnerability"

# System generates patch
prompt = f"""
Generate a secure fix for: {finding}

Current code:
{vulnerable_code}

Provide:
1. Fixed code using parameterized queries
2. Explanation of the fix
3. Test to verify the fix
"""

# Returns actionable code
response = {
    "fixed_code": "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
    "explanation": "Use parameterized queries to prevent injection...",
    "test_code": "def test_sql_injection_prevented():..."
}
```

#### 3. Contextual Exploration
```python
# User wants to understand attack chain
finding = "Backdoor pattern detected"

# System traces full attack path
prompt = f"""
Trace how this backdoor could be exploited:
{finding}

Analyze:
- Entry points
- Execution flow
- Data exfiltration paths
- Persistence mechanisms
"""

# Detailed attack narrative
response = {
    "attack_chain": [
        "1. Attacker triggers npm postinstall",
        "2. Script downloads secondary payload",
        "3. Establishes reverse shell",
        "4. Exfiltrates AWS credentials"
    ],
    "severity": "CRITICAL",
    "blast_radius": "Full AWS account compromise"
}
```

## 4. Implementation Priority

### Phase 1: Credit System (Week 1)
- [ ] MSSQL schema for credits
- [ ] Credit deduction middleware
- [ ] Balance check APIs
- [ ] Monthly reset job

### Phase 2: Claude Integration (Week 1)
- [ ] Add Anthropic provider to llm_config
- [ ] Update prompt templates for Claude
- [ ] Cost tracking per model
- [ ] A/B test Haiku vs GPT-3.5

### Phase 3: Interactive API (Week 2)
- [ ] Session management
- [ ] Investigation endpoints
- [ ] Chat functionality
- [ ] Context preservation

### Phase 4: Dashboard UI (Week 2-3)
- [ ] Credit balance widget
- [ ] Interactive finding explorer
- [ ] Chat interface
- [ ] Remediation code viewer

## 5. Pricing Strategy

### Credit Packages
```
Anonymous:         0 credits         (No access)
Free (Logged in): 50 credits/month   (~50 scans)
Pro:            5000 credits/month   ($29/mo)
Elite:         15000 credits/month   ($79/mo)
Team:          50000 credits/pool    ($199/mo)
Enterprise:    Unlimited              ($499/mo+)

Add-on Packs:
- 1000 credits:  $5
- 5000 credits:  $20
- 20000 credits: $70

Naming Alternatives for Elite tier:
- **Elite** (chosen) - Conveys premium without plus
- Advance - Progressive tier
- Expert - Professional focus
- Premium - Classic upgrade
- Master - Expertise level
```

### ROI Calculation
- Claude Haiku cost: $0.002/scan
- Sell at: $0.029/scan (via Pro subscription)
- Margin: **93.1%**
- Break-even: 35 Pro users

## 6. Competitive Advantages

### vs Snyk/Socket.dev
- **Interactive exploration** instead of static reports
- **Credit transparency** - users see exactly what they pay for
- **Model choice** - pick speed vs depth
- **Conversation memory** - contextual follow-ups

### vs GitHub Copilot Security
- **Dedicated security focus** vs general coding
- **8-phase static + LLM** vs LLM-only
- **Quarantine workflow** vs inline warnings
- **Credit control** vs unlimited (potential abuse)

## 7. Success Metrics

- **Conversion Rate**: Free → Pro (target 5%)
- **Credit Utilization**: 60% of allocated credits used
- **Interactive Sessions**: 30% of scans go interactive
- **False Positive Reports**: <10% after investigation
- **Churn Rate**: <5% monthly for Pro users

## Next Steps

1. **Immediate**: Get Claude API key, test Haiku performance
2. **Week 1**: Implement credit system in MSSQL
3. **Week 2**: Build interactive API endpoints
4. **Week 3**: Dashboard UI for chat interface
5. **Week 4**: Launch to 10 beta users, gather feedback

This transforms Sigil from a "scan and forget" tool to an **AI security companion** that helps developers understand and fix issues interactively.