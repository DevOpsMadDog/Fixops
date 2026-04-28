/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type MgrFindingResponse = {
    id: string;
    pattern_id: string;
    category: string;
    severity: string;
    name: string;
    file_path: string;
    line_number: number;
    matched_value: string;
    scan_type: string;
    commit_sha: (string | null);
    commit_author: (string | null);
    commit_date: (string | null);
    introduced_at: (string | null);
    compliance_tags: Array<string>;
    rotation_status: string;
    first_seen: string;
    last_seen: string;
};

