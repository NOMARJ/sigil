/**
 * Sigil Forge MCP Tools
 * Discovery and curation tools for AI agent skills and MCP servers
 */
import { z } from "zod";
export interface ToolMatch {
    name: string;
    ecosystem: "skill" | "mcp";
    category: string;
    description: string;
    capabilities: string[];
    trust_score: number;
    verdict: string;
    install_command?: string;
    github_url?: string;
    compatibility_signals?: string[];
}
export interface ForgeStack {
    name: string;
    use_case: string;
    description: string;
    tools: ToolMatch[];
    install_instructions: string[];
    trust_summary: {
        overall_risk: string;
        highest_risk_tool?: string;
        lowest_risk_tool?: string;
        average_trust_score: number;
    };
}
export interface ToolCheckResult {
    name: string;
    ecosystem: "skill" | "mcp";
    category: string;
    capabilities: string[];
    trust_score: number;
    verdict: string;
    permissions: {
        env_vars?: string[];
        file_access?: string[];
        network?: string[];
        system_calls?: string[];
    };
    alternatives?: ToolMatch[];
    last_scanned?: string;
    findings_summary?: {
        critical: number;
        high: number;
        medium: number;
        low: number;
    };
}
export declare const forgeSearchSchema: {
    query: z.ZodString;
    type: z.ZodDefault<z.ZodOptional<z.ZodEnum<["skill", "mcp", "both"]>>>;
};
export declare function forgeSearch({ query, type }: {
    query: string;
    type?: "skill" | "mcp" | "both";
}): Promise<{
    content: {
        type: "text";
        text: string;
    }[];
}>;
export declare const forgeStackSchema: {
    use_case: z.ZodString;
};
export declare function forgeStack({ use_case }: {
    use_case: string;
}): Promise<{
    content: {
        type: "text";
        text: string;
    }[];
}>;
export declare const forgeCheckSchema: {
    name: z.ZodString;
    ecosystem: z.ZodEnum<["skill", "mcp"]>;
};
export declare function forgeCheck({ name, ecosystem }: {
    name: string;
    ecosystem: "skill" | "mcp";
}): Promise<{
    content: {
        type: "text";
        text: string;
    }[];
}>;
