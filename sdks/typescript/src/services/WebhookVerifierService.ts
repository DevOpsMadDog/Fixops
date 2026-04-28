/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__webhook_verifier_router__DetectRequest } from '../models/apps__api__webhook_verifier_router__DetectRequest';
import type { apps__api__webhook_verifier_router__VerifyRequest } from '../models/apps__api__webhook_verifier_router__VerifyRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class WebhookVerifierService {
    /**
     * Auto Verify
     * Auto-detect the webhook provider from request headers and verify the signature.
     *
     * Reads the raw request body and all headers.  The ``X-Webhook-Secret-<Provider>``
     * header (e.g. ``X-Webhook-Secret-Github``) is used to pass the shared secret
     * without exposing it in the JSON body.  Alternatively, callers can supply secrets
     * via the ``X-Webhook-Secrets`` JSON header: ``{"github": "s3cr3t"}``.
     *
     * Returns a VerificationResult JSON object.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static autoVerifyApiV1WebhooksVerifyPost(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/webhooks/verify/',
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
     * Verification Stats
     * Return webhook verification pass/fail rates per provider for the current org.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static verificationStatsApiV1WebhooksVerifyStatsGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/webhooks/verify/stats',
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
     * Detect Provider
     * Detect the webhook provider from a set of HTTP headers (dry-run, no verification).
     *
     * Returns ``{"provider": "<name>"}`` or ``{"provider": null}`` if unrecognised.
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static detectProviderApiV1WebhooksVerifyDetectPost(
        requestBody: apps__api__webhook_verifier_router__DetectRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/webhooks/verify/detect',
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
     * Verify Provider
     * Verify a webhook against a specific named provider.
     *
     * ``provider`` must be one of: github, gitlab, jira, servicenow, slack,
     * pagerduty, stripe, custom.
     * @param provider
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static verifyProviderApiV1WebhooksVerifyProviderPost(
        provider: string,
        requestBody: apps__api__webhook_verifier_router__VerifyRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/webhooks/verify/{provider}',
            path: {
                'provider': provider,
            },
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
}
