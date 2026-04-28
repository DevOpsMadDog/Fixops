/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__cloud_compliance_router__AssessmentCreate = {
    /**
     * aws/azure/gcp/multi
     */
    cloud_provider?: string;
    /**
     * cis_aws_v1.5 / nist_800_53 / soc2 / etc.
     */
    framework: string;
    scope?: Record<string, any>;
    total_controls?: number;
};

