/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type LocalStackScanRequest = {
    /**
     * LocalStack endpoint URL
     */
    endpoint_url?: string;
    /**
     * AWS region to scan
     */
    region?: string;
    /**
     * AWS services to scan (s3, iam, ec2)
     */
    services?: Array<string>;
};

