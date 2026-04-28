/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__cloud_drift_router__BaselineCreate = {
    /**
     * Cloud resource identifier
     */
    resource_id: string;
    /**
     * ec2 / s3 / rds / lambda / sg / vpc
     */
    resource_type?: string;
    /**
     * Human-readable resource name
     */
    resource_name?: string;
    /**
     * Expected configuration from IaC
     */
    expected_config?: Record<string, any>;
    /**
     * terraform / cloudformation / manual
     */
    source?: string;
    /**
     * prod / staging / dev
     */
    environment?: string;
};

