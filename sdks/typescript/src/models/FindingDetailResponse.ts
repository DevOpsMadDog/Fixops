/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__findings_routes__TimelineEvent } from './apps__api__findings_routes__TimelineEvent';
import type { CommentResponse } from './CommentResponse';
/**
 * Complete finding detail.
 */
export type FindingDetailResponse = {
    id: string;
    title: string;
    description: (string | null);
    severity: string;
    status: string;
    connector: string;
    asset_id: (string | null);
    cve_id: (string | null);
    risk_score: number;
    created_at: string;
    updated_at: string;
    last_seen: string;
    assigned_to: (string | null);
    assigned_team: (string | null);
    pipeline_history: Array<Record<string, any>>;
    related_findings: Array<string>;
    council_verdict: (Record<string, any> | null);
    playbook_runs: Array<Record<string, any>>;
    comments: Array<CommentResponse>;
    audit_trail: Array<apps__api__findings_routes__TimelineEvent>;
};

