/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__council_enhanced_router__FeedbackRequest } from '../models/apps__api__council_enhanced_router__FeedbackRequest';
import type { apps__api__council_enhanced_router__FeedbackResponse } from '../models/apps__api__council_enhanced_router__FeedbackResponse';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class CouncilService {
    /**
     * Model accuracy report (last 30 days)
     * Return accuracy metrics per model over the last N days.
     *
     * Shows each model's prediction accuracy and current voting weight.
     * Weights are adjusted automatically as outcomes are fed back via /feedback.
     * @param windowDays Rolling window in days
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getCalibrationApiV1CouncilCalibrationGet(
        windowDays: number = 30,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/council/calibration',
            query: {
                'window_days': windowDays,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Submit actual outcome for a verdict
     * Feed the actual outcome of a finding back to calibrate model weights.
     *
     * Call this after a human analyst (or automated verification) confirms whether
     * the council's verdict was correct. Correct predictions increase a model's weight;
     * incorrect predictions decrease it.
     * @param requestBody
     * @returns apps__api__council_enhanced_router__FeedbackResponse Successful Response
     * @throws ApiError
     */
    public static postFeedbackApiV1CouncilFeedbackPost(
        requestBody: apps__api__council_enhanced_router__FeedbackRequest,
    ): CancelablePromise<apps__api__council_enhanced_router__FeedbackResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/council/feedback',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Last 50 council decisions with accuracy
     * Return the most recent council verdicts, including accuracy where known.
     *
     * Each entry includes:
     * - verdict_id, verdict, confidence, agreement_pct
     * - escalated flag, processing_ms, created_at
     * - actual_outcome (if feedback has been submitted)
     * - accurate (True/False/None — None if no outcome yet)
     * @param limit Max verdicts to return
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getRecentVerdictsApiV1CouncilRecentVerdictsGet(
        limit: number = 50,
    ): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/council/recent-verdicts',
            query: {
                'limit': limit,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
