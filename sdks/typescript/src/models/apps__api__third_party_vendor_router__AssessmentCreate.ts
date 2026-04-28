/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__third_party_vendor_router__AssessmentCreate = {
    assessment_type?: string;
    assessor?: string;
    score?: number;
    findings_count?: number;
    critical_findings?: number;
    passed?: boolean;
    assessment_date?: (string | null);
    next_review_date?: (string | null);
    notes?: string;
};

