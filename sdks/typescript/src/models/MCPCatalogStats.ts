/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Statistics about the auto-generated tool catalog.
 */
export type MCPCatalogStats = {
    total_tools: number;
    by_category: Record<string, number>;
    by_method: Record<string, number>;
    by_tag: Record<string, number>;
    routes_skipped: number;
    generated_at: string;
    generation_time_ms: number;
    mcp_version?: string;
};

