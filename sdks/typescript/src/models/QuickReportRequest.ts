/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Quick report generation request.
 */
export type QuickReportRequest = {
    /**
     * Report type
     */
    report_type?: string;
    finding_ids?: Array<string>;
    include_remediation?: boolean;
    /**
     * Output format
     */
    format?: string;
};

