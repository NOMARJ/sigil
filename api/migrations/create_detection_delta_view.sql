-- View: detection_delta
-- Initiative 2 — State of Agent Skill Security Report
--
-- Surfaces skills where Sigil flags HIGH_RISK or CRITICAL but every
-- third-party provider (Gen, Socket, Snyk) considers the skill safe,
-- low-risk, or has not yet assessed it.  This "detection delta" quantifies
-- the gap between Sigil's specialised agent-skill analysis and general-purpose
-- security tooling.

CREATE OR ALTER VIEW detection_delta AS
SELECT
    id,
    -- public_scans stores the skill's full ID as package_name
    package_name            AS name,
    ecosystem,
    verdict,
    risk_score,
    gen_verdict,
    socket_verdict,
    snyk_verdict,
    provider_assessments_json,
    scanned_at,
    metadata_json
FROM public_scans
WHERE
    ecosystem = 'skills'
    AND verdict IN ('HIGH_RISK', 'CRITICAL')
    AND (gen_verdict    IS NULL OR gen_verdict    IN ('safe', 'low_risk', 'unknown'))
    AND (socket_verdict IS NULL OR socket_verdict IN ('safe', 'low_risk', 'unknown'))
    AND (snyk_verdict   IS NULL OR snyk_verdict   IN ('safe', 'low_risk', 'unknown'));
