/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__security_posture_maturity_router__RecordAssessmentRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Security domain
     */
    domain: string;
    /**
     * Capability being assessed
     */
    capability: string;
    /**
     * Current maturity level (1–max_level)
     */
    maturity_level: number;
    /**
     * Maximum maturity level (default 5)
     */
    max_level?: number;
    /**
     * Supporting evidence
     */
    evidence?: string;
    /**
     * Who performed the assessment
     */
    assessor?: string;
    /**
     * ISO-8601 date/time for next review
     */
    next_review?: string;
};

