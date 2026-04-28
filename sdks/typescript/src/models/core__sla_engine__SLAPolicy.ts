/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type core__sla_engine__SLAPolicy = {
    id?: string;
    name: string;
    org_id: string;
    /**
     * Deadline in hours per severity
     */
    deadlines?: Record<string, number>;
    created_at?: string;
};

