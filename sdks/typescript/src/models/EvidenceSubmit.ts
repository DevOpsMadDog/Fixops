/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type EvidenceSubmit = {
    /**
     * document | screenshot | log | config | attestation
     */
    evidence_type?: string;
    /**
     * Filename of the evidence artifact
     */
    filename?: string;
    /**
     * Brief summary of evidence content
     */
    content_summary?: string;
    /**
     * System the evidence was pulled from
     */
    source_system?: string;
    /**
     * ISO timestamp when collected (defaults to now)
     */
    collected_at?: string;
};

