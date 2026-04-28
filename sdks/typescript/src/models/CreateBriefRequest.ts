/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateBriefRequest = {
    /**
     * Brief title (required)
     */
    title: string;
    /**
     * daily | weekly | monthly | incident | executive | technical
     */
    brief_type?: string;
    /**
     * critical | high | medium | low | informational
     */
    threat_level?: string;
    /**
     * Executive summary
     */
    summary?: (string | null);
    /**
     * List of key findings
     */
    key_findings?: (Array<string> | null);
    /**
     * List of recommendations
     */
    recommendations?: (Array<string> | null);
    /**
     * draft | pending | distributed | recalled
     */
    distribution_status?: string;
    /**
     * Author name or ID
     */
    author?: (string | null);
    /**
     * Period start (ISO 8601)
     */
    period_start?: (string | null);
    /**
     * Period end (ISO 8601)
     */
    period_end?: (string | null);
};

