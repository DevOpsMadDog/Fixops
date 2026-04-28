/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to update notification preferences.
 */
export type UpdateNotificationPreferencesRequest = {
    email_enabled?: (boolean | null);
    slack_enabled?: (boolean | null);
    in_app_enabled?: (boolean | null);
    digest_frequency?: (string | null);
    quiet_hours_start?: (string | null);
    quiet_hours_end?: (string | null);
    notification_types?: (Array<string> | null);
};

