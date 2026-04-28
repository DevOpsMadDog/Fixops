/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type DeployRequest = {
    /**
     * Artifact being deployed
     */
    artifact_id: string;
    /**
     * dev|staging|prod|...
     */
    environment: string;
    /**
     * k8s cluster, cloud account, host
     */
    target?: string;
    deployed_by?: string;
};

