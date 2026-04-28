/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__security_baseline_router__AddControlRequest = {
    /**
     * Control identifier (e.g. CIS-1.1)
     */
    control_id: string;
    /**
     * Human-readable control name
     */
    control_name: string;
    /**
     * Control category
     */
    category?: string;
    /**
     * Detailed control description
     */
    description?: string;
    /**
     * Expected configuration value
     */
    expected_value: string;
    /**
     * critical | high | medium | low
     */
    severity?: string;
    /**
     * Whether check can be automated
     */
    automated_check?: boolean;
};

