/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateThreatRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Associated domain ID
     */
    domain_id?: (string | null);
    /**
     * phishing | spoofing | bec | spam | malware
     */
    threat_type?: string;
    /**
     * Source IP address of the threat
     */
    source_ip?: string;
    /**
     * Sender email address
     */
    sender?: string;
    /**
     * Email subject preview (truncated)
     */
    subject_preview?: string;
    /**
     * Domain similarity score (0-1)
     */
    similarity_score?: number;
    /**
     * detected | blocked | quarantined | released
     */
    status?: string;
};

