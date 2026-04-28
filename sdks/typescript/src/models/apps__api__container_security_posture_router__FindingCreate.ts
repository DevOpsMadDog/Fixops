/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__container_security_posture_router__FindingCreate = {
    cluster_id: string;
    namespace?: string;
    pod_name?: string;
    container_name?: string;
    finding_type?: string;
    severity?: string;
    title?: string;
    description?: string;
    remediation?: string;
    detected_at?: (string | null);
};

