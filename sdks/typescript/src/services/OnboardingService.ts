/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__onboarding_router__CompleteStepRequest } from '../models/apps__api__onboarding_router__CompleteStepRequest';
import type { apps__api__onboarding_router__StartRequest } from '../models/apps__api__onboarding_router__StartRequest';
import type { ChecklistResponse } from '../models/ChecklistResponse';
import type { ListOnboardingsResponse } from '../models/ListOnboardingsResponse';
import type { OnboardingProgressResponse } from '../models/OnboardingProgressResponse';
import type { ResetRequest } from '../models/ResetRequest';
import type { SkipStepRequest } from '../models/SkipStepRequest';
import type { StepConfigResponse } from '../models/StepConfigResponse';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class OnboardingService {
    /**
     * Start Onboarding
     * Start or resume onboarding for an organisation.
     * @param requestBody
     * @returns OnboardingProgressResponse Successful Response
     * @throws ApiError
     */
    public static startOnboardingApiV1OnboardingStartPost(
        requestBody: apps__api__onboarding_router__StartRequest,
    ): CancelablePromise<OnboardingProgressResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/onboarding/start',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Progress
     * Get current onboarding progress for an organisation.
     * @param orgId
     * @returns OnboardingProgressResponse Successful Response
     * @throws ApiError
     */
    public static getProgressApiV1OnboardingProgressGet(
        orgId: string,
    ): CancelablePromise<OnboardingProgressResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/onboarding/progress',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Complete Step
     * Mark a step as completed with optional configuration data.
     * @param step Onboarding step name (e.g. CONFIGURE_AUTH)
     * @param requestBody
     * @returns OnboardingProgressResponse Successful Response
     * @throws ApiError
     */
    public static completeStepApiV1OnboardingStepsStepCompletePost(
        step: string,
        requestBody: apps__api__onboarding_router__CompleteStepRequest,
    ): CancelablePromise<OnboardingProgressResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/onboarding/steps/{step}/complete',
            path: {
                'step': step,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Skip Step
     * Mark a step as skipped.
     * @param step Onboarding step name to skip
     * @param requestBody
     * @returns OnboardingProgressResponse Successful Response
     * @throws ApiError
     */
    public static skipStepApiV1OnboardingStepsStepSkipPost(
        step: string,
        requestBody: SkipStepRequest,
    ): CancelablePromise<OnboardingProgressResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/onboarding/steps/{step}/skip',
            path: {
                'step': step,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Step Config
     * Retrieve configuration stored when a step was completed.
     * @param step Onboarding step name
     * @param orgId
     * @returns StepConfigResponse Successful Response
     * @throws ApiError
     */
    public static getStepConfigApiV1OnboardingStepsStepConfigGet(
        step: string,
        orgId: string,
    ): CancelablePromise<StepConfigResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/onboarding/steps/{step}/config',
            path: {
                'step': step,
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
     * Reset Onboarding
     * Reset onboarding for an organisation and start over.
     * @param requestBody
     * @returns OnboardingProgressResponse Successful Response
     * @throws ApiError
     */
    public static resetOnboardingApiV1OnboardingResetPost(
        requestBody: ResetRequest,
    ): CancelablePromise<OnboardingProgressResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/onboarding/reset',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Checklist
     * Pre-flight checklist showing what is configured vs still missing.
     * @param orgId
     * @returns ChecklistResponse Successful Response
     * @throws ApiError
     */
    public static getChecklistApiV1OnboardingChecklistGet(
        orgId: string,
    ): CancelablePromise<ChecklistResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/onboarding/checklist',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Onboardings
     * Admin endpoint — list all organisation onboardings.
     * @param status Filter by status: completed | in_progress | not_started
     * @returns ListOnboardingsResponse Successful Response
     * @throws ApiError
     */
    public static listOnboardingsApiV1OnboardingListGet(
        status?: (string | null),
    ): CancelablePromise<ListOnboardingsResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/onboarding/list',
            query: {
                'status': status,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
