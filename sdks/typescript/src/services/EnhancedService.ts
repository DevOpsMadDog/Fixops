/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CompareLLMsRequest } from '../models/CompareLLMsRequest';
import type { EnhancedDecisionRequest } from '../models/EnhancedDecisionRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class EnhancedService {
    /**
     * Run Enhanced Analysis
     * Return multi-LLM consensus analysis for the supplied findings payload.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static runEnhancedAnalysisApiV1EnhancedAnalysisPost(
        requestBody: EnhancedDecisionRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/enhanced/analysis',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Compare Llms
     * Compare individual model verdicts and consensus metadata.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static compareLlmsApiV1EnhancedCompareLlmsPost(
        requestBody: CompareLLMsRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/enhanced/compare-llms',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Enhanced Capabilities
     * Expose engine telemetry and supported providers.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static enhancedCapabilitiesApiV1EnhancedCapabilitiesGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/enhanced/capabilities',
        });
    }
    /**
     * Enhanced Signals
     * Return the latest feed badges and SSVC label for the enhanced engine.
     * @param verdict
     * @param confidence
     * @returns any Successful Response
     * @throws ApiError
     */
    public static enhancedSignalsApiV1EnhancedSignalsGet(
        verdict: string = 'allow',
        confidence: number = 0.9,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/enhanced/signals',
            query: {
                'verdict': verdict,
                'confidence': confidence,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
