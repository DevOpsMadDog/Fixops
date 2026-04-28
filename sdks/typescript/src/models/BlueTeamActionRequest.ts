/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type BlueTeamActionRequest = {
    /**
     * Zero-based index of the step being responded to
     */
    step_index: number;
    /**
     * Containment action: isolate_host, block_ip, disable_account, revoke_token, quarantine_file, firewall_rule, patch_applied, escalate, monitor
     */
    action: string;
    /**
     * Who performed the action
     */
    actor?: string;
    /**
     * Action details
     */
    description?: string;
    /**
     * Was the action effective?
     */
    effective?: boolean;
};

