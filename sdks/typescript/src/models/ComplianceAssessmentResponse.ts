/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response model for compliance assessment.
 */
export type ComplianceAssessmentResponse = {
    framework: string;
    overall_score: number;
    total_controls: number;
    controls_by_automation: Record<string, number>;
    gaps: Array<Record<string, any>>;
    recommendations: Array<string>;
};

