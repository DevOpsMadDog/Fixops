/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__semgrep_router__ScanFileRequest } from '../models/apps__api__semgrep_router__ScanFileRequest';
import type { apps__api__semgrep_router__ScanResponse } from '../models/apps__api__semgrep_router__ScanResponse';
import type { apps__api__semgrep_router__ScanSummaryResponse } from '../models/apps__api__semgrep_router__ScanSummaryResponse';
import type { RulesetsResponse } from '../models/RulesetsResponse';
import type { ScanDirectoryRequest } from '../models/ScanDirectoryRequest';
import type { ScanWithConfigRequest } from '../models/ScanWithConfigRequest';
import type { SemgrepStatusResponse } from '../models/SemgrepStatusResponse';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class SemgrepScannerService {
    /**
     * Scan a filesystem directory
     * Scan a local directory for SAST findings using Semgrep.
     *
     * Returns normalized findings ingested into the Brain Pipeline.
     * Falls back to mock data when semgrep is not installed.
     * @param requestBody
     * @returns apps__api__semgrep_router__ScanResponse Successful Response
     * @throws ApiError
     */
    public static scanDirectoryApiV1ScanSemgrepDirectoryPost(
        requestBody: ScanDirectoryRequest,
    ): CancelablePromise<apps__api__semgrep_router__ScanResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/scan/semgrep/directory',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Scan a single file
     * Scan a single file for SAST findings using Semgrep.
     *
     * Falls back to mock data when semgrep is not installed.
     * @param requestBody
     * @returns apps__api__semgrep_router__ScanResponse Successful Response
     * @throws ApiError
     */
    public static scanFileApiV1ScanSemgrepFilePost(
        requestBody: apps__api__semgrep_router__ScanFileRequest,
    ): CancelablePromise<apps__api__semgrep_router__ScanResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/scan/semgrep/file',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Scan with a custom semgrep config
     * Scan a path using a custom semgrep config (registry ID, YAML file, or URL).
     *
     * Falls back to mock data when semgrep is not installed.
     * @param requestBody
     * @returns apps__api__semgrep_router__ScanResponse Successful Response
     * @throws ApiError
     */
    public static scanWithConfigApiV1ScanSemgrepConfigPost(
        requestBody: ScanWithConfigRequest,
    ): CancelablePromise<apps__api__semgrep_router__ScanResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/scan/semgrep/config',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Check semgrep availability
     * Return whether the semgrep binary is available on this host.
     *
     * When semgrep is not installed all scan endpoints return mock data.
     * @returns SemgrepStatusResponse Successful Response
     * @throws ApiError
     */
    public static semgrepStatusApiV1ScanSemgrepStatusGet(): CancelablePromise<SemgrepStatusResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/scan/semgrep/status',
        });
    }
    /**
     * List available Semgrep rulesets
     * Return the list of well-known public Semgrep rulesets from the registry.
     * @returns RulesetsResponse Successful Response
     * @throws ApiError
     */
    public static listRulesetsApiV1ScanSemgrepRulesetsGet(): CancelablePromise<RulesetsResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/scan/semgrep/rulesets',
        });
    }
    /**
     * List scan history
     * Return the scan history for the given organisation, most recent first.
     *
     * Findings are omitted from the summary; re-run a scan to get full results.
     * @param orgId Organisation identifier
     * @returns apps__api__semgrep_router__ScanSummaryResponse Successful Response
     * @throws ApiError
     */
    public static scanHistoryApiV1ScanSemgrepHistoryGet(
        orgId: string = 'default',
    ): CancelablePromise<Array<apps__api__semgrep_router__ScanSummaryResponse>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/scan/semgrep/history',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
