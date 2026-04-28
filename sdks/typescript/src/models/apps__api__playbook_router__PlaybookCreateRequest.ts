/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__playbook_router__PlaybookCreateRequest = {
    /**
     * Human-readable playbook name
     */
    name: string;
    /**
     * manual | auto_alert | scheduled
     */
    trigger_type?: string;
    trigger_conditions?: Record<string, any>;
    steps?: Array<Record<string, any>>;
    /**
     * Minimum severity to trigger
     */
    severity_filter?: string;
    enabled?: boolean;
    /**
     * Organization identifier
     */
    org_id?: string;
};

