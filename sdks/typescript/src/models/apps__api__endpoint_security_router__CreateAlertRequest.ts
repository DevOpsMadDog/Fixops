/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__endpoint_security_router__CreateAlertRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Target endpoint ID
     */
    endpoint_id: string;
    /**
     * critical/high/medium/low
     */
    severity?: string;
    /**
     * malware/ransomware/lateral_movement/privilege_escalation/data_exfil/policy_violation
     */
    alert_type?: string;
    /**
     * Alert description
     */
    description?: string;
    /**
     * open/investigating/resolved
     */
    status?: string;
};

