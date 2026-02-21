-- Sigil Threat Signature Tables
-- Run this SQL in Supabase to create extended signature and malware family tables

-- Extended signatures table with additional metadata
CREATE TABLE IF NOT EXISTS public.signatures (
    id TEXT PRIMARY KEY,
    phase TEXT NOT NULL,
    pattern TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    -- Extended fields
    category TEXT DEFAULT 'unknown',
    weight NUMERIC(4,1) DEFAULT 1.0,
    language JSONB DEFAULT '["*"]'::jsonb,
    cve JSONB DEFAULT '[]'::jsonb,
    malware_families JSONB DEFAULT '[]'::jsonb,
    false_positive_likelihood TEXT DEFAULT 'unknown',
    created DATE DEFAULT CURRENT_DATE
);

-- Malware families metadata table
CREATE TABLE IF NOT EXISTS public.malware_families (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    first_seen TEXT,
    ecosystem TEXT,
    severity TEXT DEFAULT 'HIGH',
    description TEXT,
    iocs JSONB DEFAULT '[]'::jsonb,
    signature_ids JSONB DEFAULT '[]'::jsonb,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_signatures_category ON public.signatures(category);
CREATE INDEX IF NOT EXISTS idx_signatures_severity ON public.signatures(severity);
CREATE INDEX IF NOT EXISTS idx_signatures_phase ON public.signatures(phase);
CREATE INDEX IF NOT EXISTS idx_signatures_updated ON public.signatures(updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_malware_families_ecosystem ON public.malware_families(ecosystem);
CREATE INDEX IF NOT EXISTS idx_malware_families_severity ON public.malware_families(severity);

-- Comments
COMMENT ON TABLE public.signatures IS 'Threat detection signatures for malicious code patterns';
COMMENT ON COLUMN public.signatures.weight IS 'Score multiplier (0-20) for risk calculation';
COMMENT ON COLUMN public.signatures.false_positive_likelihood IS 'Expected false positive rate: very_low, low, medium, high, very_high';
COMMENT ON COLUMN public.signatures.language IS 'Programming languages this signature targets';
COMMENT ON COLUMN public.signatures.cve IS 'Related CVE identifiers';
COMMENT ON COLUMN public.signatures.malware_families IS 'Known malware families using this pattern';

COMMENT ON TABLE public.malware_families IS 'Known malware families and their characteristics';
COMMENT ON COLUMN public.malware_families.iocs IS 'Indicators of Compromise (URLs, hashes, etc.)';
COMMENT ON COLUMN public.malware_families.signature_ids IS 'Signature IDs that detect this family';

-- Grant permissions (adjust as needed for your setup)
GRANT SELECT ON public.signatures TO anon, authenticated;
GRANT SELECT ON public.malware_families TO anon, authenticated;
GRANT ALL ON public.signatures TO service_role;
GRANT ALL ON public.malware_families TO service_role;
