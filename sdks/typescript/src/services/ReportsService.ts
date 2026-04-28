/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__reports_router__ReportCreate } from '../models/apps__api__reports_router__ReportCreate';
import type { apps__api__reports_router__ReportResponse } from '../models/apps__api__reports_router__ReportResponse';
import type { PaginatedReportResponse } from '../models/PaginatedReportResponse';
import type { ReportScheduleCreate } from '../models/ReportScheduleCreate';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class ReportsService {
    /**
     * List Reports
     * List all reports with optional filtering.
     * @param reportType
     * @param limit
     * @param offset
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns PaginatedReportResponse Successful Response
     * @throws ApiError
     */
    public static listReportsApiV1ReportsGet(
        reportType?: (string | null),
        limit: number = 100,
        offset?: number,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<PaginatedReportResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/reports',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'report_type': reportType,
                'limit': limit,
                'offset': offset,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Create Report
     * Create and generate a new report with real file output.
     * @param requestBody
     * @returns apps__api__reports_router__ReportResponse Successful Response
     * @throws ApiError
     */
    public static createReportApiV1ReportsPost(
        requestBody: apps__api__reports_router__ReportCreate,
    ): CancelablePromise<apps__api__reports_router__ReportResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/reports',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Generate Report
     * Generate a new report (alias for POST /api/v1/reports).
     *
     * This is the preferred endpoint for UI report generation.
     * @param requestBody
     * @returns apps__api__reports_router__ReportResponse Successful Response
     * @throws ApiError
     */
    public static generateReportApiV1ReportsGeneratePost(
        requestBody: apps__api__reports_router__ReportCreate,
    ): CancelablePromise<apps__api__reports_router__ReportResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/reports/generate',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Report Stats
     * Get report statistics and metrics.
     * @param startDate
     * @param endDate
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getReportStatsApiV1ReportsStatsGet(
        startDate?: (string | null),
        endDate?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/reports/stats',
            query: {
                'start_date': startDate,
                'end_date': endDate,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Report
     * Get report details by ID.
     * @param id
     * @returns apps__api__reports_router__ReportResponse Successful Response
     * @throws ApiError
     */
    public static getReportApiV1ReportsIdGet(
        id: string,
    ): CancelablePromise<apps__api__reports_router__ReportResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/reports/{id}',
            path: {
                'id': id,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Download Report
     * Download report file.
     * @param id
     * @returns any Successful Response
     * @throws ApiError
     */
    public static downloadReportApiV1ReportsIdDownloadGet(
        id: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/reports/{id}/download',
            path: {
                'id': id,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Report File
     * Get the actual report file for download.
     * @param id
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getReportFileApiV1ReportsIdFileGet(
        id: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/reports/{id}/file',
            path: {
                'id': id,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Schedule Report
     * Schedule a recurring report.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static scheduleReportApiV1ReportsSchedulePost(
        requestBody: ReportScheduleCreate,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/reports/schedule',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Schedules
     * List all scheduled reports.
     * @param limit
     * @param offset
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listSchedulesApiV1ReportsSchedulesListGet(
        limit: number = 100,
        offset?: number,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/reports/schedules/list',
            query: {
                'limit': limit,
                'offset': offset,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Templates
     * List all report templates.
     * @param limit
     * @param offset
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listTemplatesApiV1ReportsTemplatesListGet(
        limit: number = 100,
        offset?: number,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/reports/templates/list',
            query: {
                'limit': limit,
                'offset': offset,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Export Sarif
     * Export findings as SARIF format with real data.
     *
     * Generates a SARIF 2.1.0 compliant report from actual findings data.
     * @param startDate
     * @param endDate
     * @param includeSuppressed
     * @returns any Successful Response
     * @throws ApiError
     */
    public static exportSarifApiV1ReportsExportSarifPost(
        startDate?: (string | null),
        endDate?: (string | null),
        includeSuppressed: boolean = false,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/reports/export/sarif',
            query: {
                'start_date': startDate,
                'end_date': endDate,
                'include_suppressed': includeSuppressed,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Export Csv
     * Export findings as CSV format with real data.
     *
     * Generates a CSV report from actual findings data.
     * @param startDate
     * @param endDate
     * @param includeHeaders
     * @returns any Successful Response
     * @throws ApiError
     */
    public static exportCsvApiV1ReportsExportCsvPost(
        startDate?: (string | null),
        endDate?: (string | null),
        includeHeaders: boolean = true,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/reports/export/csv',
            query: {
                'start_date': startDate,
                'end_date': endDate,
                'include_headers': includeHeaders,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Download Csv Export
     * Download a previously generated CSV export file.
     *
     * Args:
     * export_id: The export ID returned from the export_csv endpoint.
     *
     * Returns:
     * The CSV file as a download.
     * @param exportId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static downloadCsvExportApiV1ReportsExportCsvExportIdDownloadGet(
        exportId: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/reports/export/csv/{export_id}/download',
            path: {
                'export_id': exportId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Export Json
     * Export findings as JSON format with real data.
     * @param startDate
     * @param endDate
     * @returns any Successful Response
     * @throws ApiError
     */
    public static exportJsonApiV1ReportsExportJsonGet(
        startDate?: (string | null),
        endDate?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/reports/export/json',
            query: {
                'start_date': startDate,
                'end_date': endDate,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
