/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Aggregated session record for a user within a time window.
 */
export type UserSession = {
    id?: string;
    user_email: string;
    started_at: string;
    last_active: string;
    duration_minutes: number;
    activity_count: number;
    org_id: string;
};

