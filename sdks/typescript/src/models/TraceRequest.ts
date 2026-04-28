/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type TraceRequest = {
    vulnerability_id: string;
    source_file?: string;
    source_line?: number;
    git_commit?: string;
    container_image?: string;
    k8s_namespace?: string;
    k8s_deployment?: string;
    cloud_service?: string;
    cloud_region?: string;
    internet_facing?: boolean;
};

