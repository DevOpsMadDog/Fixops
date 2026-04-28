/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { api__dtrack_router__SBOMUploadRequest } from '../models/api__dtrack_router__SBOMUploadRequest';
import type { Body_upload_sbom_file_api_v1_dtrack_sbom_upload_file_post } from '../models/Body_upload_sbom_file_api_v1_dtrack_sbom_upload_file_post';
import type { TagRequest } from '../models/TagRequest';
import type { VEXUploadRequest } from '../models/VEXUploadRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class DependencyTrackService {
    /**
     * Dtrack Health
     * Check Dependency-Track connectivity and version.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static dtrackHealthApiV1DtrackHealthGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/dtrack/health',
        });
    }
    /**
     * List Projects
     * List all Dependency-Track projects (applications with SBOMs).
     * @param page
     * @param pageSize
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listProjectsApiV1DtrackProjectsGet(
        page: number = 1,
        pageSize: number = 100,
    ): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/dtrack/projects',
            query: {
                'page': page,
                'page_size': pageSize,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Lookup Project
     * Lookup or create a Dependency-Track project by name + version.
     * @param name
     * @param version
     * @returns any Successful Response
     * @throws ApiError
     */
    public static lookupProjectApiV1DtrackProjectsLookupGet(
        name: string,
        version: string = 'latest',
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/dtrack/projects/lookup',
            query: {
                'name': name,
                'version': version,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Upload Sbom Json
     * Upload a CycloneDX or SPDX SBOM (JSON body). DTrack auto-detects format.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static uploadSbomJsonApiV1DtrackSbomUploadPost(
        requestBody: api__dtrack_router__SBOMUploadRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/dtrack/sbom/upload',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Upload Sbom File
     * Upload a CycloneDX or SPDX SBOM file. DTrack auto-detects format.
     * @param projectName Target project name
     * @param formData
     * @param projectVersion
     * @returns any Successful Response
     * @throws ApiError
     */
    public static uploadSbomFileApiV1DtrackSbomUploadFilePost(
        projectName: string,
        formData: Body_upload_sbom_file_api_v1_dtrack_sbom_upload_file_post,
        projectVersion: string = 'latest',
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/dtrack/sbom/upload-file',
            query: {
                'project_name': projectName,
                'project_version': projectVersion,
            },
            formData: formData,
            mediaType: 'multipart/form-data',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Sbom Processing Status
     * Check whether a previously uploaded SBOM has been fully processed.
     * @param token
     * @returns any Successful Response
     * @throws ApiError
     */
    public static sbomProcessingStatusApiV1DtrackSbomStatusTokenGet(
        token: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/dtrack/sbom/status/{token}',
            path: {
                'token': token,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Export Sbom
     * Export the current SBOM for a project in CycloneDX format.
     * @param projectUuid
     * @param fmt
     * @returns any Successful Response
     * @throws ApiError
     */
    public static exportSbomApiV1DtrackSbomExportProjectUuidGet(
        projectUuid: string,
        fmt: string = 'json',
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/dtrack/sbom/export/{project_uuid}',
            path: {
                'project_uuid': projectUuid,
            },
            query: {
                'fmt': fmt,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Project Components
     * Fetch all components (dependencies) for a project.
     * @param projectUuid
     * @param page
     * @param pageSize
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getProjectComponentsApiV1DtrackComponentsProjectUuidGet(
        projectUuid: string,
        page: number = 1,
        pageSize: number = 100,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/dtrack/components/{project_uuid}',
            path: {
                'project_uuid': projectUuid,
            },
            query: {
                'page': page,
                'page_size': pageSize,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Search Components
     * Search components across entire portfolio. Use for impact analysis
     * (e.g., 'which applications use log4j?').
     * @param query Component name to search (e.g. 'log4j')
     * @param page
     * @param pageSize
     * @returns any Successful Response
     * @throws ApiError
     */
    public static searchComponentsApiV1DtrackComponentsSearchGet(
        query: string,
        page: number = 1,
        pageSize: number = 100,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/dtrack/components/search',
            query: {
                'query': query,
                'page': page,
                'page_size': pageSize,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Findings
     * Fetch vulnerability findings for a project from Dependency-Track.
     * @param projectUuid
     * @param page
     * @param pageSize
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getFindingsApiV1DtrackFindingsProjectUuidGet(
        projectUuid: string,
        page: number = 1,
        pageSize: number = 100,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/dtrack/findings/{project_uuid}',
            path: {
                'project_uuid': projectUuid,
            },
            query: {
                'page': page,
                'page_size': pageSize,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Licenses
     * Fetch component license data for a project.
     * @param projectUuid
     * @param page
     * @param pageSize
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getLicensesApiV1DtrackLicensesProjectUuidGet(
        projectUuid: string,
        page: number = 1,
        pageSize: number = 100,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/dtrack/licenses/{project_uuid}',
            path: {
                'project_uuid': projectUuid,
            },
            query: {
                'page': page,
                'page_size': pageSize,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Policy Violations
     * Fetch policy violations for a project.
     * @param projectUuid
     * @param page
     * @param pageSize
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getPolicyViolationsApiV1DtrackViolationsProjectUuidGet(
        projectUuid: string,
        page: number = 1,
        pageSize: number = 100,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/dtrack/violations/{project_uuid}',
            path: {
                'project_uuid': projectUuid,
            },
            query: {
                'page': page,
                'page_size': pageSize,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Upload Vex
     * Upload a CycloneDX VEX document to apply analysis decisions
     * (e.g., mark findings as not_affected, false_positive, in_triage).
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static uploadVexApiV1DtrackVexUploadPost(
        requestBody: VEXUploadRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/dtrack/vex/upload',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Tag Project
     * Add tags to a project for FixOps categorization and filtering.
     * @param projectUuid
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static tagProjectApiV1DtrackProjectsProjectUuidTagsPost(
        projectUuid: string,
        requestBody: TagRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/dtrack/projects/{project_uuid}/tags',
            path: {
                'project_uuid': projectUuid,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Portfolio Metrics
     * Fetch portfolio-wide vulnerability metrics from Dependency-Track.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static portfolioMetricsApiV1DtrackMetricsPortfolioGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/dtrack/metrics/portfolio',
        });
    }
    /**
     * Project Metrics
     * Fetch project-level vulnerability metrics from Dependency-Track.
     * @param projectUuid
     * @returns any Successful Response
     * @throws ApiError
     */
    public static projectMetricsApiV1DtrackMetricsProjectProjectUuidGet(
        projectUuid: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/dtrack/metrics/project/{project_uuid}',
            path: {
                'project_uuid': projectUuid,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
