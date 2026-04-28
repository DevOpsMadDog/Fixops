/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Ingest Nuclei JSON template hits (no Docker required).
 */
export type DastIngestNucleiRequest = {
    org_id: string;
    /**
     * Nuclei -j output (list of hit dicts, single dict, or JSONL string)
     */
    items: (Record<string, any> | string);
    target?: (string | null);
    scan_id?: (string | null);
    mirror_to_bug_bounty?: boolean;
};

