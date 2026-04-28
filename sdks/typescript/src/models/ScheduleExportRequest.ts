/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ScheduleExportRequest = {
    org_id: string;
    format?: string;
    filters?: Record<string, any>;
    /**
     * Frequency: hourly, daily, weekly
     */
    frequency?: string;
};

