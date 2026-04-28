/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__cwpp_router__RegisterWorkloadRequest = {
    /**
     * Unique workload identifier
     */
    workload_id: string;
    /**
     * One of: ['container', 'vm', 'lambda', 'cloud_run', 'ecs_task', 'kubernetes_pod']
     */
    workload_type: string;
    /**
     * Human-readable workload name
     */
    name: string;
    /**
     * Optional metadata: image, namespace, node, labels, cloud_account
     */
    metadata?: Record<string, any>;
    /**
     * Organisation ID
     */
    org_id?: string;
};

