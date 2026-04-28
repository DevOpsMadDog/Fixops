/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RecordAlertBody = {
    /**
     * suspicious_command | data_exfiltration | privilege_escalation | policy_violation | anomaly
     */
    alert_type: string;
    /**
     * critical | high | medium | low | info
     */
    severity?: string;
    /**
     * Alert description
     */
    description?: string;
    /**
     * Command or context that triggered the alert
     */
    command_context?: string;
};

