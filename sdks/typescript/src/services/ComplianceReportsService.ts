/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__compliance_reports_router__GenerateReportRequest } from '../models/apps__api__compliance_reports_router__GenerateReportRequest';
import type { ReportSummary } from '../models/ReportSummary';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class ComplianceReportsService {
    /**
     * List Frameworks
     * Return the list of supported compliance frameworks.
     * @returns string Successful Response
     * @throws ApiError
     */
    public static listFrameworksApiV1ComplianceReportsFrameworksGet(): CancelablePromise<Array<string>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/compliance-reports/frameworks',
        });
    }
    /**
     * Generate Report
     * Generate and persist a compliance report for the requested framework.
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static generateReportApiV1ComplianceReportsGeneratePost(
        requestBody: apps__api__compliance_reports_router__GenerateReportRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/compliance-reports/generate',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'org_id': orgId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Reports
     * List stored compliance reports with optional framework filter.
     * @param framework
     * @param limit
     * @param offset
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns ReportSummary Successful Response
     * @throws ApiError
     */
    public static listReportsApiV1ComplianceReportsGet(
        framework?: (string | null),
        limit: number = 50,
        offset?: number,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Array<ReportSummary>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/compliance-reports/',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'framework': framework,
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
     * Get Report
     * Retrieve a full compliance report including all sections.
     * @param reportId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getReportApiV1ComplianceReportsReportIdGet(
        reportId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/compliance-reports/{report_id}',
            path: {
                'report_id': reportId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Delete Report
     * Delete a compliance report.
     * @param reportId
     * @returns void
     * @throws ApiError
     */
    public static deleteReportApiV1ComplianceReportsReportIdDelete(
        reportId: string,
    ): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/v1/compliance-reports/{report_id}',
            path: {
                'report_id': reportId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Export Json
     * Export report as JSON.
     * @param reportId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static exportJsonApiV1ComplianceReportsReportIdExportJsonGet(
        reportId: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/compliance-reports/{report_id}/export/json',
            path: {
                'report_id': reportId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Export Html
     * Export report as HTML.
     * @param reportId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static exportHtmlApiV1ComplianceReportsReportIdExportHtmlGet(
        reportId: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/compliance-reports/{report_id}/export/html',
            path: {
                'report_id': reportId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Export Csv
     * Export report as CSV.
     * @param reportId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static exportCsvApiV1ComplianceReportsReportIdExportCsvGet(
        reportId: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/compliance-reports/{report_id}/export/csv',
            path: {
                'report_id': reportId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Export Markdown
     * Export report as Markdown.
     * @param reportId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static exportMarkdownApiV1ComplianceReportsReportIdExportMarkdownGet(
        reportId: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/compliance-reports/{report_id}/export/markdown',
            path: {
                'report_id': reportId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Gaps
     * Return only the gap controls from a compliance report.
     * @param reportId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getGapsApiV1ComplianceReportsReportIdGapsGet(
        reportId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/compliance-reports/{report_id}/gaps',
            path: {
                'report_id': reportId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
