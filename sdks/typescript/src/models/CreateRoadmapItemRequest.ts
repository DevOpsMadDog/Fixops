/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateRoadmapItemRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Security domain
     */
    domain: string;
    /**
     * Capability to improve
     */
    capability: string;
    /**
     * Current maturity level
     */
    current_level: number;
    /**
     * Target maturity level
     */
    target_level: number;
    /**
     * critical/high/medium/low
     */
    priority?: string;
    /**
     * low/medium/high/very-high
     */
    effort?: string;
    /**
     * Planned timeline (e.g. Q3 2026)
     */
    timeline?: string;
    /**
     * Responsible owner
     */
    owner?: string;
};

