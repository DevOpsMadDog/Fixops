/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__compliance_automation_router__CollectEvidenceRequest = {
    /**
     * Target framework (SOC2, PCI-DSS, HIPAA, FedRAMP, ISO27001, NIST-800-53, CMMC)
     */
    framework: string;
    /**
     * Specific control ID; omit to collect for all controls in the framework
     */
    control_id?: (string | null);
    /**
     * Organisation identifier
     */
    org_id?: (string | null);
};

