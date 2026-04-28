/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Regulatory notification response.
 */
export type NotificationResponse = {
    id: string;
    incident_id: string;
    framework: string;
    deadline_hours: (number | null);
    detection_time: string;
    deadline_at: (string | null);
    notified_at: (string | null);
    is_overdue: boolean;
    status: string;
    template: string;
    hours_remaining: (number | null);
};

