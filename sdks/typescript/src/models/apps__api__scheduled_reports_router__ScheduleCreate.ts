/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__scheduled_reports_router__ScheduleCreate = {
    name: string;
    report_type?: string;
    frequency?: string;
    hour_utc?: number;
    day_of_week?: (number | null);
    day_of_month?: (number | null);
    recipients?: Array<string>;
    slack_webhook_url?: string;
    format?: string;
};

