/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__attack_path_router__AnalyzeRequest = {
    /**
     * Compromised host node ID
     */
    entry_point: string;
    /**
     * Specific target node ID (None = all crown jewels)
     */
    target?: (string | null);
    /**
     * Maximum lateral movement hops
     */
    max_hops?: number;
    /**
     * Organisation ID
     */
    org_id?: string;
};

