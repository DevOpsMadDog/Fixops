/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type StartSessionBody = {
    /**
     * User initiating the session
     */
    user: string;
    /**
     * ssh | rdp | database | api | console | winrm | telnet
     */
    session_type?: string;
    /**
     * Target host name or FQDN
     */
    target_host: string;
    /**
     * Target IP address
     */
    target_ip?: string;
    /**
     * System or PAM that initiated the session
     */
    initiated_by?: string;
};

