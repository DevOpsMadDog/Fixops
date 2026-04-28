/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { EvidenceSource } from './EvidenceSource';
/**
 * A single automatically-collected compliance evidence artifact.
 */
export type AutoEvidence = {
    id?: string;
    source: EvidenceSource;
    control_id: string;
    framework: string;
    content_hash: string;
    collected_at?: string;
    expires_at?: (string | null);
    verified?: boolean;
    org_id: string;
    summary?: string;
    raw_content?: string;
};

