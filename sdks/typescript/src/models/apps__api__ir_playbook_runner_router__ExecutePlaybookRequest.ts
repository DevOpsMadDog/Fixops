/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__ir_playbook_runner_router__ExecutePlaybookRequest = {
    /**
     * Playbook ID, e.g. 'phishing_response'
     */
    playbook_id: string;
    /**
     * Incident context. Supported keys: title, description, severity, org_id, incident_id, affected_assets (list), affected_users (list), attacker_ip, attacker_ips (list), tags (list).
     */
    incident: Record<string, any>;
    /**
     * Override incident ID
     */
    incident_id?: (string | null);
};

