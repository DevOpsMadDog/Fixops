/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AnalyzeDiffRequest } from '../models/AnalyzeDiffRequest';
import type { AnalyzePRRequest } from '../models/AnalyzePRRequest';
import type { AnalyzeResponse } from '../models/AnalyzeResponse';
import type { apps__api__material_change_router__AnalyzeRequest } from '../models/apps__api__material_change_router__AnalyzeRequest';
import type { ClassifyRequest } from '../models/ClassifyRequest';
import type { CommitAnalyzeRequest } from '../models/CommitAnalyzeRequest';
import type { MaterialChangeResponse } from '../models/MaterialChangeResponse';
import type { ReviewChecklistRequest } from '../models/ReviewChecklistRequest';
import type { WebhookResponse } from '../models/WebhookResponse';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class MaterialChangesService {
    /**
     * Analyze Changes
     * Classify git changes as COSMETIC, MATERIAL, or BREAKING.
     *
     * Accepts either raw diff text or a commit SHA + repo path.
     * Returns a per-file risk classification and optional blast radius.
     * @param requestBody
     * @returns AnalyzeResponse Successful Response
     * @throws ApiError
     */
    public static analyzeChangesApiV1ChangesAnalyzePost(
        requestBody: apps__api__material_change_router__AnalyzeRequest,
    ): CancelablePromise<AnalyzeResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/changes/analyze',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Github Webhook
     * Handle GitHub push-event webhooks.
     *
     * Validates the HMAC signature (if GITHUB_WEBHOOK_SECRET is set), then
     * analyses the diff for the head commit and returns the classification.
     *
     * GitHub sends a ``push`` event with a JSON payload containing ``commits``
     * and ``head_commit`` fields.
     *
     * Security hardening applied:
     * - Rate limiting: 10 requests/minute per IP
     * - Payload size limit: 1 MB
     * - SSRF validation on any URLs in the payload
     * @param xGithubEvent
     * @param xHubSignature256
     * @returns WebhookResponse Successful Response
     * @throws ApiError
     */
    public static githubWebhookApiV1ChangesWebhookPost(
        xGithubEvent?: (string | null),
        xHubSignature256?: (string | null),
    ): CancelablePromise<WebhookResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/changes/webhook',
            headers: {
                'x-github-event': xGithubEvent,
                'x-hub-signature-256': xHubSignature256,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Health
     * Health check for the material change detection service.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static healthApiV1ChangesHealthGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/changes/health',
        });
    }
    /**
     * Analyze Diff
     * Analyze a raw diff string and classify changes.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static analyzeDiffApiV1ChangesAnalyzeDiffPost(
        requestBody: AnalyzeDiffRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/changes/analyze-diff',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Analyze Pr
     * Analyze all file diffs in a PR.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static analyzePrApiV1ChangesAnalyzePrPost(
        requestBody: AnalyzePRRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/changes/analyze-pr',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Classify
     * Classify file diffs without full analysis.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static classifyApiV1ChangesClassifyPost(
        requestBody: ClassifyRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/changes/classify',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Review Checklist
     * Generate a review checklist based on change categories.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static reviewChecklistApiV1ChangesReviewChecklistPost(
        requestBody: ReviewChecklistRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/changes/review-checklist',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Change Velocity
     * Get change velocity metrics for a repository.
     * @param repoId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static changeVelocityApiV1ChangesVelocityRepoIdGet(
        repoId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/changes/velocity/{repo_id}',
            path: {
                'repo_id': repoId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Risk Profile
     * Get risk profile for a repository based on recent changes.
     * @param repoId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static riskProfileApiV1ChangesRiskProfileRepoIdGet(
        repoId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/changes/risk-profile/{repo_id}',
            path: {
                'repo_id': repoId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Receive GitHub push webhook → SAST → LLM Council → incident
     * Accept a GitHub push webhook, run SAST on changed files, assess materiality,
     * and open an incident if the change is security-material.
     *
     * Security:
     * - HMAC-SHA256 verified when GITHUB_WEBHOOK_SECRET is set
     * - Rate-limited: 10 requests/minute per IP
     * - Payload capped at 1 MB
     * @param xGithubEvent
     * @param xHubSignature256
     * @returns MaterialChangeResponse Successful Response
     * @throws ApiError
     */
    public static pushWebhookApiV1ChangesMaterialChangeWebhookPost(
        xGithubEvent?: (string | null),
        xHubSignature256?: (string | null),
    ): CancelablePromise<MaterialChangeResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/changes/material-change/webhook',
            headers: {
                'x-github-event': xGithubEvent,
                'x-hub-signature-256': xHubSignature256,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Manually analyze a commit SHA for materiality
     * Manually trigger push-event materiality analysis for a given commit.
     *
     * Useful for CI/CD pipelines and manual investigation.
     * @param requestBody
     * @returns MaterialChangeResponse Successful Response
     * @throws ApiError
     */
    public static analyzeCommitManualApiV1ChangesMaterialChangeAnalyzePost(
        requestBody: CommitAnalyzeRequest,
    ): CancelablePromise<MaterialChangeResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/changes/material-change/analyze',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List recent material change analyses
     * Return the most recent push-event analyses, newest first.
     * @param limit
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listRecentMaterialChangesApiV1ChangesMaterialChangeRecentGet(
        limit: number = 50,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/changes/material-change/recent',
            query: {
                'limit': limit,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get a specific push-event analysis by ID
     * Fetch a single push-event analysis record by its UUID.
     * @param changeId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getMaterialChangeApiV1ChangesMaterialChangeChangeIdGet(
        changeId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/changes/material-change/{change_id}',
            path: {
                'change_id': changeId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
