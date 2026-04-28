/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__security_gap_analysis_router__CreateAssessmentRequest = {
    /**
     * Organisation ID
     */
    org_id: string;
    /**
     * SOC2|ISO27001|PCI-DSS|HIPAA|NIST-CSF|NIST-800-53|CIS|FedRAMP|GDPR|SOX
     */
    framework: string;
    /**
     * Assessment name
     */
    assessment_name: string;
    /**
     * Total control count
     */
    total_controls?: number;
    /**
     * Assessor name
     */
    assessor?: string;
    /**
     * Next review date (ISO)
     */
    next_review?: string;
};

