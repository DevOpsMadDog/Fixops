/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type PipelineCreate = {
    name: string;
    repo_url?: string;
    branch?: string;
    ci_platform?: string;
    security_gates_enabled?: number;
    sast_enabled?: number;
    dast_enabled?: number;
    sca_enabled?: number;
    secret_scan_enabled?: number;
    container_scan_enabled?: number;
};

