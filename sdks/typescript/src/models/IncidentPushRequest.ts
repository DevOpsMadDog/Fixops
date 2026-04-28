/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type IncidentPushRequest = {
    /**
     * Connection ID
     */
    connection_id: string;
    /**
     * List of ALDECI alerts to push
     */
    alerts: Array<Record<string, any>>;
    /**
     * Default assignment group sys_id
     */
    assignment_group?: string;
};

