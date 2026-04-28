/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AddDomainThreatRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Domain to mark as malicious
     */
    domain: string;
    /**
     * Threat type: c2/phishing/malware/spam/botnet
     */
    threat_type: string;
    /**
     * Confidence score 0-1
     */
    confidence?: number;
    /**
     * Source of the intelligence
     */
    source?: string;
    /**
     * Associated IOCs
     */
    iocs?: Array<string>;
};

