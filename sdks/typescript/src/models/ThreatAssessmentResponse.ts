/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Threat assessment result.
 */
export type ThreatAssessmentResponse = {
    threat_score: number;
    risk_level: string;
    indicators?: Array<string>;
    recommended_action?: string;
};

