/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__cloud_resource_inventory_router__ResourceCreate = {
    /**
     * Cloud provider resource identifier
     */
    resource_id: string;
    /**
     * Human-readable resource name
     */
    resource_name?: string;
    /**
     * aws/azure/gcp/alibaba/oracle/ibm/digitalocean
     */
    provider?: string;
    /**
     * compute/storage/database/network/iam/container/serverless/cdn/dns/load_balancer
     */
    resource_type?: string;
    /**
     * Cloud region
     */
    region?: string;
    /**
     * Cloud account/subscription ID
     */
    account_id?: string;
    /**
     * Resource tags
     */
    tags?: Record<string, any>;
    /**
     * running/stopped/terminated/unknown/pending
     */
    resource_state?: string;
};

