/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ContainerCreate = {
    org_id?: string;
    container_id: string;
    image_name: string;
    image_tag?: string;
    pod_name?: string;
    namespace?: string;
    cluster?: string;
    runtime_status?: string;
    privileged?: boolean;
    host_network?: boolean;
    security_score?: number;
};

