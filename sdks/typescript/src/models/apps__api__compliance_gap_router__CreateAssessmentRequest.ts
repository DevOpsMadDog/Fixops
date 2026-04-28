/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__compliance_gap_router__CreateAssessmentRequest = {
    /**
     * SOC2|ISO27001|NIST|PCI-DSS|HIPAA|GDPR|CIS
     */
    framework: string;
    /**
     * Name of the assessment
     */
    assessment_name: string;
    /**
     * Expected control count
     */
    total_controls?: number;
};

