/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__grc_router__AssessmentCreate = {
    framework_id: string;
    assessor?: string;
    assessment_date?: (string | null);
    scope?: string;
    overall_score?: number;
    findings_count?: number;
    /**
     * draft|in_progress|completed|approved
     */
    status?: string;
};

