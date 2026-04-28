/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__threat_deception_management_router__RecordInteractionRequest = {
    /**
     * scan | login_attempt | file_access | network_probe | data_exfil
     */
    interaction_type?: string;
    /**
     * Attacker source IP
     */
    source_ip?: string;
    user_agent?: string;
    payload_preview?: string;
    attacker_fingerprint?: string;
    occurred_at?: (string | null);
};

