/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__cloud_governance_router__PolicyCreate = {
    name: string;
    /**
     * access/cost/security/compliance/resource/tagging
     */
    policy_type: string;
    /**
     * aws/azure/gcp/multi_cloud/on_premise
     */
    cloud_provider?: string;
    /**
     * advisory/warning/blocking
     */
    enforcement?: string;
    description?: string;
};

