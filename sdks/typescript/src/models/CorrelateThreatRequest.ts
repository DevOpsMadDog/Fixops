/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CorrelateThreatRequest = {
    org_id?: string;
    /**
     * Asset to correlate threat against
     */
    asset_id: string;
    /**
     * Threat identifier (auto-generated if omitted)
     */
    threat_id?: (string | null);
    /**
     * malware/apt/ransomware/phishing/exploit/insider
     */
    threat_type?: string;
    /**
     * Confidence 0-100
     */
    confidence?: number;
    /**
     * critical/high/medium/low
     */
    severity?: string;
    /**
     * Whether an IOC matched
     */
    ioc_matched?: boolean;
};

