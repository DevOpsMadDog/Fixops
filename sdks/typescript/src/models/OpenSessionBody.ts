/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type OpenSessionBody = {
    /**
     * Privileged account ID
     */
    account_id: string;
    /**
     * ssh | rdp | database | api | console | jump_host
     */
    session_type?: string;
    /**
     * Target system hostname/IP
     */
    target_system?: string;
};

