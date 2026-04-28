/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__vendor_compliance_router__ComplianceCheckRequest = {
    /**
     * Organisation identifier
     */
    org_id?: string;
    /**
     * DPA signed and current
     */
    data_processing_agreement?: boolean;
    /**
     * Security questionnaire completed
     */
    security_questionnaire?: boolean;
    /**
     * Recent penetration test report provided
     */
    pen_test_report?: boolean;
    /**
     * SOC 2 report available
     */
    soc2_report?: boolean;
    /**
     * GDPR compliance confirmed
     */
    gdpr_compliance?: boolean;
    /**
     * Cyber insurance certificate on file
     */
    insurance_certificate?: boolean;
};

