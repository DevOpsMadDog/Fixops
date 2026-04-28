/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ManualAssessRequest = {
    ssl_score?: (number | null);
    headers_score?: (number | null);
    dns_score?: (number | null);
    vulnerability_score?: (number | null);
    data_handling_score?: (number | null);
    /**
     * Who performed the assessment
     */
    assessor?: string;
    /**
     * Assessment notes
     */
    notes?: string;
    validity_days?: number;
};

