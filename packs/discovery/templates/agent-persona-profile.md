# AI Agent Consumer Persona Template

*Use when AI agents will interact with this product as consumers,
intermediaries, or evaluators. Delete if not applicable.*

```markdown
---
type: agent-persona
created: {{DATE}}
challenge: {{product name}}
agent_type: {{Shopping / Research / Procurement / Operations / Negotiation / Orchestration}}
confidence: {{🟢 HIGH / 🟡 MED / 🟠 LOW}}
---

## {{AGENT TYPE}} Agent

**Type:** {{agent_type}}
**Industry confidence:** {{HIGH — observed in production / MED — piloted / LOW — speculative}}
**Principal:** {{Who does this agent serve? Human consumer / Enterprise buyer / Other agent}}

### Operational Context

- **Platform examples:** {{OpenAI Operator / Claude MCP / Perplexity / Amazon Buy for Me / Custom}}
- **Autonomy level:** {{Advisory only / Execute with approval / Fully autonomous}}
- **Decision authority:** {{Budget limits, category restrictions, approval gates}}
- **Memory:** {{Stateless / Session-persistent / Long-term}}

### Needs (Agent's Equivalent of Human Needs)

- **Data:** {{What information formats does it require?}}
- **Speed:** {{What latency is acceptable?}}
- **Reliability:** {{What uptime/accuracy is required?}}
- **Structured access:** {{APIs, protocols, schemas needed?}}
- **Trust signals:** {{How does it verify authenticity, quality?}}
- **Rollback:** {{What happens when things go wrong?}}

### Frustrations (Agent's Equivalent of Pain Points)

- {{What blocks task completion?}}
- {{What forces escalation to human?}}
- {{What causes bad recommendations?}}
- {{What makes it choose a competitor?}}

### Decision Logic

- **Primary optimisation:** {{Price / Speed / Quality / Compliance / Principal preference}}
- **Tiebreakers:** {{When options are equivalent, what tips it?}}
- **Deal-breakers:** {{What causes instant rejection?}}

### Evaluation Criteria

- **Quality signals used:** {{ratings, review volume, response time, data completeness}}
- **Human signals ignored:** {{brand prestige, visual design, emotional storytelling}}
- **Machine signals prioritised:** {{schema.org, API response time, data freshness}}

### Interaction Pattern

- **Discovery:** {{How does it find you?}}
- **Evaluation:** {{What does it inspect?}}
- **Transaction:** {{How does it buy/integrate?}}
- **Post-transaction:** {{How does it manage ongoing?}}

### Failure Modes

- {{Missing/inconsistent data?}}
- {{API downtime?}}
- {{Principal disagreement with recommendation?}}
- {{Cascading failures across services?}}
```
