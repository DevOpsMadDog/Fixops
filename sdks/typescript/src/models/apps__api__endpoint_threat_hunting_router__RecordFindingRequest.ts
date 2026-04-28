/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__endpoint_threat_hunting_router__RecordFindingRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Associated hunt ID
     */
    hunt_id: string;
    /**
     * Endpoint where finding was detected
     */
    endpoint_id?: string;
    /**
     * Finding type
     */
    finding_type?: string;
    /**
     * Severity: critical/high/medium/low
     */
    severity?: string;
    /**
     * Process name
     */
    process_name?: string;
    /**
     * Command line observed
     */
    command_line?: string;
    /**
     * File path involved
     */
    file_path?: string;
    /**
     * Finding status
     */
    status?: string;
    /**
     * ISO-8601 detection timestamp
     */
    detected_at?: (string | null);
};

