# Inter-Agent Handoff Protocol

## Purpose
This document defines the standard contract for context passing between agents in the NOMARK system. It ensures consistent, traceable, and efficient handoffs during multi-agent workflows.

## Overview
The handoff protocol enables seamless transitions between agents working on related tasks, preserving context and preventing information loss during agent switches.

## Handoff Block Schema

Every agent handoff MUST include the following structured block written to `progress.md`:

```markdown
## AGENT HANDOFF
---
from: [sending_agent_name]
to: [receiving_agent_name]
story_id: [current_story_id]
timestamp: [ISO 8601 timestamp]
status: [in_progress | blocked | escalated | completed]

### Context Summary
[2-3 sentence summary of work completed and current state]

### Work Completed
- [Specific action taken]
- [Files modified with line numbers]
- [Tests added/modified]

### Blockers
- [Any blocking issues encountered]
- [Dependencies needed]

### Next Action Required
- [Specific next step for receiving agent]
- [Expected outcome]

### Artifacts
- Files modified: [list of files with paths]
- Tests: [test files created/modified]
- Documentation: [docs updated]

### Notes for Receiving Agent
[Any special considerations, decisions made, or context the next agent needs]
---
```

## Required Fields

### Mandatory Fields
- `from`: Name of the sending agent
- `to`: Name of the receiving agent  
- `story_id`: Current story being worked on
- `timestamp`: ISO 8601 formatted timestamp
- `status`: Current status of the work
- `Context Summary`: Brief overview of current state
- `Next Action Required`: Clear directive for receiving agent

### Optional Fields
- `Blockers`: Only if blockers exist
- `Notes for Receiving Agent`: Only if special context needed
- `Artifacts`: Can be empty if no files modified

## Status Values

- **in_progress**: Work is ongoing, handoff for continuation
- **blocked**: Work cannot proceed, escalation may be needed
- **escalated**: Requires human or higher-tier agent intervention
- **completed**: Subtask complete, handing off for next phase

## Receiving Agent Startup Sequence

When an agent starts and detects a handoff block:

1. **Read handoff block** from `progress.md` BEFORE any other action
2. **Validate handoff** - Confirm this agent is the intended recipient
3. **Load context** - Read all files listed in artifacts
4. **Acknowledge receipt** - Add acknowledgment to progress.md:
   ```markdown
   ## HANDOFF ACKNOWLEDGED
   agent: [receiving_agent_name]
   received_from: [sending_agent_name]
   timestamp: [ISO 8601 timestamp]
   action: [Starting | Reviewing | Continuing] [specific task]
   ```
5. **Continue work** from the specified next action

## Ralph.sh Implementation

The ralph.sh orchestrator implements this protocol in team mode:

### Writing Handoffs
```bash
# Between agent invocations in team mode
write_handoff() {
    local from_agent="$1"
    local to_agent="$2"
    local story_id="$3"
    local status="$4"
    
    cat >> progress.md << HANDOFF
## AGENT HANDOFF
---
from: $from_agent
to: $to_agent
story_id: $story_id
timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)
status: $status
...
---
HANDOFF
}
```

### Team Mode Coordination
In team mode, ralph.sh:
1. Writes handoff blocks between each agent invocation
2. Ensures receiving agents read handoff blocks first
3. Tracks handoff chain for audit trail
4. Detects handoff failures (no acknowledgment within 30 seconds)

## Multi-Agent Workflow Example

### Scenario: Complex Feature Implementation

1. **code-architect** → **backend-architect**
   ```markdown
   ## AGENT HANDOFF
   ---
   from: code-architect
   to: backend-architect
   story_id: FEAT-123
   status: in_progress
   
   ### Context Summary
   Designed high-level architecture for payment processing feature. 
   Database schema and API contracts defined.
   
   ### Next Action Required
   - Implement payment service with Stripe integration
   - Create API endpoints as per specification in docs/api/payments.yaml
   ---
   ```

2. **backend-architect** → **tdd-specialist**
   ```markdown
   ## AGENT HANDOFF
   ---
   from: backend-architect
   to: tdd-specialist
   story_id: FEAT-123
   status: in_progress
   
   ### Context Summary
   Payment service core implementation complete.
   Needs comprehensive test coverage.
   
   ### Next Action Required
   - Write unit tests for PaymentService class
   - Add integration tests for Stripe webhook handlers
   ---
   ```

## Handoff Validation Rules

### Valid Handoffs
- Agent specified in `to` field exists
- Story ID matches current active story
- Status is one of the defined values
- Required fields are present

### Invalid Handoffs (Trigger Escalation)
- Circular handoff detected (A→B→A within same story)
- Missing required fields
- Handoff to non-existent agent
- Status conflicts (completed but has blockers)

## Error Handling

### Handoff Failures
If a handoff fails (receiving agent doesn't acknowledge):
1. Wait 30 seconds for acknowledgment
2. Retry handoff once
3. If still no acknowledgment, trigger ESCALATION
4. Log failure to progress.md with timestamp

### Recovery Protocol
When recovering from failed handoff:
1. Last successful agent resumes work
2. Failed handoff marked in progress.md
3. Human intervention may be required
4. Context preserved for manual recovery

## Best Practices

### DO
- Keep context summaries concise (2-3 sentences)
- List specific files and line numbers
- Use clear, actionable next steps
- Include test file paths when relevant
- Timestamp everything

### DON'T
- Don't include entire code blocks in handoffs
- Don't assume context without explicit statement
- Don't skip acknowledgment step
- Don't modify another agent's handoff block
- Don't handoff without clear next action

## Integration Points

### With progress.md
- Handoff blocks are appended to progress.md
- Handoffs are part of permanent record
- Search for "## AGENT HANDOFF" to find all handoffs

### With ralph.sh
- Orchestrator writes handoff blocks automatically
- Validates handoff acknowledgments
- Tracks handoff metrics (success rate, avg time)

### With escalation protocol
- Failed handoffs trigger escalation
- Escalation reason includes handoff failure details
- Handoff chain preserved for debugging

## Metrics and Monitoring

Track these metrics for handoff health:
- **Acknowledgment rate**: % of handoffs acknowledged
- **Acknowledgment time**: Time from handoff to acknowledgment  
- **Handoff chain length**: Average number of handoffs per story
- **Failure rate**: % of handoffs that fail/timeout
- **Circular detection**: Count of circular handoff attempts

## Version History

- **1.0.0** (2024-03-17): Initial protocol definition
- Defines schema, validation rules, and ralph.sh integration
- Establishes acknowledgment protocol and error handling