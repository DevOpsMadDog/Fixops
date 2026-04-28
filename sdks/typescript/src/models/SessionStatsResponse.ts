/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Session statistics for an org.
 */
export type SessionStatsResponse = {
    org_id: string;
    active_count: number;
    avg_duration_seconds: number;
    by_user: Record<string, number>;
};

