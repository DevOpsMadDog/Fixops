/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { Body_detect_scanner_type_api_v1_scanner_ingest_detect_post } from '../models/Body_detect_scanner_type_api_v1_scanner_ingest_detect_post';
import type { Body_upload_scanner_output_api_v1_scanner_ingest_upload_post } from '../models/Body_upload_scanner_output_api_v1_scanner_ingest_upload_post';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class ScannerIngestService {
    /**
     * List Scanner Ingest
     * List supported scanners and ingestion stats.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listScannerIngestApiV1ScannerIngestGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/scanner-ingest/',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Upload Scanner Output
     * Upload a scanner output file for ingestion.
     *
     * Supports: ZAP, Burp, Nessus, OpenVAS, Bandit, Checkmarx, SonarQube,
     * Fortify, Veracode, Nikto, Nuclei, Nmap, Snyk, Prowler, Checkov, Gitleaks.
     * Plus existing: SARIF, CycloneDX, SPDX, VEX, Trivy, Grype, Semgrep, Dependabot.
     *
     * If scanner_type is not provided, auto-detection is used.
     * Set pipeline=true to push findings into the Brain Pipeline immediately.
     * @param formData
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static uploadScannerOutputApiV1ScannerIngestUploadPost(
        formData: Body_upload_scanner_output_api_v1_scanner_ingest_upload_post,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/scanner-ingest/upload',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'org_id': orgId,
            },
            formData: formData,
            mediaType: 'multipart/form-data',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Webhook Ingest
     * Receive scanner output via webhook (raw body).
     *
     * Set up your CI/CD to POST scanner output directly:
     * curl -X POST https://aldeci/api/v1/scanner-ingest/webhook/zap \
     * -H "X-API-Key: $KEY" \
     * -H "Content-Type: application/json" \
     * --data-binary @zap-report.json
     * @param scannerType
     * @param appId
     * @param component
     * @param pipeline
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static webhookIngestApiV1ScannerIngestWebhookScannerTypePost(
        scannerType: string,
        appId: string = '',
        component: string = '',
        pipeline: boolean = false,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/scanner-ingest/webhook/{scanner_type}',
            path: {
                'scanner_type': scannerType,
            },
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'app_id': appId,
                'component': component,
                'pipeline': pipeline,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Detect Scanner Type
     * Detect scanner type from uploaded file without processing.
     * Returns the detected scanner type and confidence score.
     * @param formData
     * @returns any Successful Response
     * @throws ApiError
     */
    public static detectScannerTypeApiV1ScannerIngestDetectPost(
        formData: Body_detect_scanner_type_api_v1_scanner_ingest_detect_post,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/scanner-ingest/detect',
            formData: formData,
            mediaType: 'multipart/form-data',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Supported Scanners
     * List all supported scanner types grouped by category.
     *
     * Returns 25+ scanner types across SAST, DAST, SCA, infrastructure, cloud.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listSupportedScannersApiV1ScannerIngestSupportedGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/scanner-ingest/supported',
        });
    }
    /**
     * Ingestion Stats
     * Return scanner ingestion statistics from the analytics database.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static ingestionStatsApiV1ScannerIngestStatsGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/scanner-ingest/stats',
        });
    }
    /**
     * Scanner Ingest Health
     * Scanner ingest service health check.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static scannerIngestHealthApiV1ScannerIngestHealthGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/scanner-ingest/health',
        });
    }
    /**
     * Scanner Ingest Status
     * Scanner ingest service status with real ingestion data.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static scannerIngestStatusApiV1ScannerIngestStatusGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/scanner-ingest/status',
        });
    }
}
