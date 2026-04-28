/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateBaselineRequest = {
    /**
     * Descriptive name for the baseline
     */
    baseline_name: string;
    /**
     * server | workstation | network_device | cloud_instance | container | database | application
     */
    target_type: string;
    /**
     * CIS | NIST | STIG | ISO27001 | PCI-DSS | custom
     */
    framework: string;
    /**
     * Baseline version string
     */
    version?: string;
    /**
     * Username of creator
     */
    created_by: string;
};

