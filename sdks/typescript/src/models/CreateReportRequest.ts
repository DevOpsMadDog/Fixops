/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateReportRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Report name
     */
    report_name: string;
    /**
     * executive/board/audit/compliance/operational/monthly/quarterly/annual
     */
    report_type?: string;
    /**
     * ciso/board/executives/auditors/regulators/team
     */
    audience?: string;
    /**
     * Period start ISO date
     */
    period_start: string;
    /**
     * Period end ISO date
     */
    period_end: string;
    /**
     * Author or system that generated the report
     */
    generated_by?: string;
};

