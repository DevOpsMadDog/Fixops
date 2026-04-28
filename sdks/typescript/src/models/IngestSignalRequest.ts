/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type IngestSignalRequest = {
    /**
     * endpoint/network/cloud/identity/email/application/threat_intel
     */
    source_type?: string;
    source_system?: string;
    /**
     * malware/lateral_movement/credential_theft/exfiltration/c2/anomaly/policy_violation
     */
    signal_type?: string;
    /**
     * critical/high/medium/low/info
     */
    severity?: string;
    /**
     * IP, hostname, username, file hash, etc.
     */
    entity_id?: string;
    /**
     * host/ip/user/file/process/domain
     */
    entity_type?: string;
    raw_data?: Record<string, any>;
    confidence?: number;
    ingested_at?: (string | null);
};

