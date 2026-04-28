/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response model for a report.
 */
export type apps__api__reports_router__ReportResponse = {
    id: string;
    name: string;
    report_type: string;
    format: string;
    status: string;
    parameters: Record<string, any>;
    file_path: (string | null);
    file_size: (number | null);
    generated_by: (string | null);
    error_message: (string | null);
    created_at: string;
    completed_at: (string | null);
};

