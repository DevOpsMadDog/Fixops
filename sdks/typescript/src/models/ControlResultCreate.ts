/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ControlResultCreate = {
    control_id: string;
    control_name?: string;
    section?: string;
    /**
     * critical/high/medium/low/info
     */
    severity?: string;
    /**
     * passed/failed/not_applicable/manual_check
     */
    status?: string;
    evidence?: string;
    resource_id?: string;
    resource_type?: string;
    resource_name?: string;
    region?: string;
    remediation?: string;
    auto_remediated?: boolean;
};

