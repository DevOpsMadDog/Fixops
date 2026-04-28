/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for adding evidence to an incident.
 */
export type apps__api__ir_playbook_router__AddEvidenceRequest = {
    /**
     * ID of the collector (user, tool, or system)
     */
    collector_id: string;
    /**
     * Evidence type: log, screenshot, pcap, image, etc.
     */
    evidence_type: string;
    /**
     * Human-readable description of this evidence
     */
    description: string;
    /**
     * Raw evidence content (text, base64 for binary)
     */
    raw_content: string;
};

