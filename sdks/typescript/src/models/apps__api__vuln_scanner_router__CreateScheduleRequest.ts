/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__vuln_scanner_router__CreateScheduleRequest = {
    scanner_id: string;
    name: string;
    target_type?: string;
    targets?: Array<string>;
    frequency?: string;
    cron_expression?: string;
    enabled?: boolean;
    last_run?: (string | null);
    next_run?: (string | null);
    status?: string;
};

