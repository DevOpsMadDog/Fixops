/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__deception_analytics_router__RecordInteractionRequest = {
    /**
     * ID of the triggered deception asset
     */
    asset_id: string;
    /**
     * Attacker source IP address
     */
    source_ip: string;
    /**
     * recon | lateral_movement | credential_access | execution | persistence | exfiltration | discovery | collection | impact
     */
    attacker_technique?: string;
    confidence_score?: number;
    threat_actor_signature?: string;
    /**
     * critical | high | medium | low
     */
    severity?: string;
    details?: string;
    detected_at?: (string | null);
};

