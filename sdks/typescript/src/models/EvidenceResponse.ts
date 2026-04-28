/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Evidence chain item response.
 */
export type EvidenceResponse = {
    id: string;
    incident_id: string;
    collector_id: string;
    evidence_type: string;
    description: string;
    sha256_hash: string;
    collected_at: string;
    previous_hash: string;
    chain_sequence: number;
    chain_valid?: boolean;
};

