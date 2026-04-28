/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateAttributionRequest = {
    org_id?: string;
    /**
     * Incident identifier (required)
     */
    incident_id: string;
    /**
     * Threat actor id (optional)
     */
    actor_id?: string;
    /**
     * Confidence: confirmed, likely, possible, unlikely
     */
    confidence?: string;
    /**
     * Supporting evidence map
     */
    evidence?: Record<string, any>;
    /**
     * Analyst who created the attribution
     */
    analyst?: string;
    /**
     * ISO datetime of attribution
     */
    attribution_date?: (string | null);
    /**
     * Analyst notes
     */
    notes?: string;
};

