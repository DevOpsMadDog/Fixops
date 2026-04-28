/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type TicketCreate = {
    title: string;
    cve_id?: string;
    severity?: string;
    cvss_score?: number;
    affected_assets?: Array<string>;
    assignee_id?: string;
    assignee_team?: string;
    priority?: string;
    due_date?: (string | null);
    resolution_notes?: string;
    source_engine?: string;
    tags?: Array<string>;
};

