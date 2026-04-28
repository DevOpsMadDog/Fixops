/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response from push-event analysis.
 */
export type MaterialChangeResponse = {
    id: string;
    commit_sha: string;
    repository: string;
    branch: string;
    author: string;
    changed_files_count: number;
    blast_radius: (Record<string, any> | null);
    sast_findings_count: number;
    is_material: boolean;
    materiality_reasons: Array<string>;
    incident_id: (string | null);
    analyzed_at: string;
};

