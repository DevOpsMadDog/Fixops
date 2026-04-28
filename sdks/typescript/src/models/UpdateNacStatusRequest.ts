/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type UpdateNacStatusRequest = {
    org_id?: string;
    /**
     * allowed/restricted/quarantined/blocked
     */
    nac_status: string;
    reason?: string;
};

