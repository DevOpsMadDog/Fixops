/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__iam_sso_router__SyncRequest } from '../models/apps__api__iam_sso_router__SyncRequest';
import type { IngestVendorRequest } from '../models/IngestVendorRequest';
import type { ProviderEntry } from '../models/ProviderEntry';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class IamSsoConnectorService {
    /**
     * List Providers
     * Return the list of vendor providers this connector replaces.
     * @returns ProviderEntry Successful Response
     * @throws ApiError
     */
    public static listProvidersApiV1ConnectorsIamSsoProvidersGet(): CancelablePromise<Array<ProviderEntry>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/connectors/iam-sso/providers',
        });
    }
    /**
     * Health
     * Probe Keycloak; return reachability + last-sync summary.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static healthApiV1ConnectorsIamSsoHealthGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/connectors/iam-sso/health',
        });
    }
    /**
     * Sync
     * Provision realms + ingest audit events into ALDECI engines.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static syncApiV1ConnectorsIamSsoSyncPost(
        requestBody: apps__api__iam_sso_router__SyncRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/connectors/iam-sso/sync',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Status
     * Return cached last-sync result (or empty if never run).
     * @returns any Successful Response
     * @throws ApiError
     */
    public static statusApiV1ConnectorsIamSsoStatusGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/connectors/iam-sso/status',
        });
    }
    /**
     * Ingest Vendor
     * Ingest already-collected raw events from Okta / Auth0 / Entra / Keycloak.
     *
     * Each event is normalized via the vendor adapter, then mirrored to the same
     * SecurityFindingsEngine + AccessAnomalyEngine path used by ``/sync``.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static ingestVendorApiV1ConnectorsIamSsoIngestVendorPost(
        requestBody: IngestVendorRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/connectors/iam-sso/ingest-vendor',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
