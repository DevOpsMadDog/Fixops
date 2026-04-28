/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { Body_validate_batch_api_v1_validate_batch_post } from '../models/Body_validate_batch_api_v1_validate_batch_post';
import type { Body_validate_input_api_v1_validate_input_post } from '../models/Body_validate_input_api_v1_validate_input_post';
import type { CompatibilityReport } from '../models/CompatibilityReport';
import type { ValidationResult } from '../models/ValidationResult';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class ValidationService {
    /**
     * Validate Input
     * Validate a security tool output without persisting it.
     *
     * This endpoint tests whether FixOps can successfully parse and normalize
     * the provided file. Use this to verify compatibility before deployment.
     *
     * Args:
     * file: The security tool output file to validate
     * input_type: Optional hint for input type (sarif, sbom, cve, vex, cnapp)
     *
     * Returns:
     * ValidationResult with parsing status, detected format, and any warnings
     * @param formData
     * @param inputType
     * @returns ValidationResult Successful Response
     * @throws ApiError
     */
    public static validateInputApiV1ValidateInputPost(
        formData: Body_validate_input_api_v1_validate_input_post,
        inputType?: (string | null),
    ): CancelablePromise<ValidationResult> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/validate/input',
            query: {
                'input_type': inputType,
            },
            formData: formData,
            mediaType: 'multipart/form-data',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Validate Batch
     * Validate multiple security tool outputs at once.
     *
     * Use this to test a complete set of tool outputs before deployment.
     * @param formData
     * @returns CompatibilityReport Successful Response
     * @throws ApiError
     */
    public static validateBatchApiV1ValidateBatchPost(
        formData: Body_validate_batch_api_v1_validate_batch_post,
    ): CancelablePromise<CompatibilityReport> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/validate/batch',
            formData: formData,
            mediaType: 'multipart/form-data',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Supported Formats
     * List all supported input formats and their versions.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getSupportedFormatsApiV1ValidateSupportedFormatsGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/validate/supported-formats',
        });
    }
    /**
     * Validation Health
     * Validation service health check.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static validationHealthApiV1ValidateHealthGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/validate/health',
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
     * Validation Status
     * Validation service status (alias for /health).
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static validationStatusApiV1ValidateStatusGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/validate/status',
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
}
