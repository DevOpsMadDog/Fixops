/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AssessSupplierRequest = {
    /**
     * Organisation identifier
     */
    org_id?: string;
    /**
     * Supplier holds relevant security certifications
     */
    security_certifications?: boolean;
    /**
     * Supplier has a history of incidents
     */
    incident_history?: boolean;
    /**
     * Supplier is financially stable
     */
    financial_stability?: boolean;
    /**
     * Supplier is compliant with required standards
     */
    compliance_status?: boolean;
    /**
     * Supplier has a business continuity plan
     */
    business_continuity?: boolean;
};

