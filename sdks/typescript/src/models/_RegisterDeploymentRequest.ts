/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type _RegisterDeploymentRequest = {
    artifact_id: string;
    environment?: string;
    deployed_by?: string;
    k8s_namespace?: (string | null);
    k8s_deployment?: (string | null);
    k8s_pod_count?: number;
    cloud_provider?: string;
    cloud_region?: (string | null);
    cloud_service?: (string | null);
    cloud_instance_ids?: Array<string>;
    internet_facing?: boolean;
    previous_deployment_id?: (string | null);
};

