/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type MonitorSession = {
    id?: string;
    target: string;
    interval_seconds?: number;
    started_at?: string;
    last_snapshot_id?: (string | null);
    snapshot_count?: number;
    active?: boolean;
};

