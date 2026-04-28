/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AddIntegrationRequest = {
    /**
     * Source tool ID
     */
    tool_id: string;
    /**
     * Target tool or system name
     */
    integrated_with: string;
    /**
     * api | syslog | webhook | agent | manual
     */
    integration_type: string;
    /**
     * active | inactive | broken | pending
     */
    status?: (string | null);
};

