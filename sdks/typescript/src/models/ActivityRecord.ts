/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * A single recorded user-activity event.
 */
export type ActivityRecord = {
    id?: string;
    user_email: string;
    activity_type: string;
    details?: Record<string, any>;
    org_id: string;
    recorded_at?: string;
    acknowledged?: boolean;
    acknowledged_by?: (string | null);
    acknowledged_at?: (string | null);
};

