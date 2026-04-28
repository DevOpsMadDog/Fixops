/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ScheduleReevalRequest = {
    /**
     * Organisation ID
     */
    org_id: string;
    /**
     * SBOM asset / export ID to re-evaluate
     */
    sbom_id: string;
    /**
     * Cron expression
     */
    cron_expr?: string;
};

