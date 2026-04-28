/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__report_scheduler_router__CreateScheduleRequest = {
    name: string;
    /**
     * One of: ['executive_summary', 'vulnerability_digest', 'compliance_status', 'threat_intel_brief', 'kpi_scorecard']
     */
    report_type: string;
    /**
     * One of: ['daily', 'weekly', 'monthly']
     */
    frequency: string;
    recipients?: Array<string>;
    /**
     * One of: ['email', 'slack']
     */
    channels?: Array<string>;
    /**
     * One of: ['json', 'html', 'pdf']
     */
    format?: string;
    filters?: Record<string, any>;
    org_id?: string;
};

