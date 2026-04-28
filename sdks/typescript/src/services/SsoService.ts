/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__sso_router__SessionResponse } from '../models/apps__api__sso_router__SessionResponse';
import type { Body_sso_callback_api_v1_auth_sso__provider__callback_get } from '../models/Body_sso_callback_api_v1_auth_sso__provider__callback_get';
import type { Body_sso_callback_api_v1_auth_sso__provider__callback_post } from '../models/Body_sso_callback_api_v1_auth_sso__provider__callback_post';
import type { CallbackResponse } from '../models/CallbackResponse';
import type { LogoutResponse } from '../models/LogoutResponse';
import type { ProviderListResponse } from '../models/ProviderListResponse';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class SsoService {
    /**
     * Sso Status
     * SSO status — whether SSO is enabled and which providers are configured.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static ssoStatusApiV1AuthSsoGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/auth/sso',
        });
    }
    /**
     * Sso Status
     * SSO status — whether SSO is enabled and which providers are configured.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static ssoStatusApiV1AuthSsoGet1(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/auth/sso/',
        });
    }
    /**
     * List Sso Providers
     * List all configured SSO providers.
     * @returns ProviderListResponse Successful Response
     * @throws ApiError
     */
    public static listSsoProvidersApiV1AuthSsoProvidersGet(): CancelablePromise<ProviderListResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/auth/sso/providers',
        });
    }
    /**
     * Sso Login
     * Initiate SSO flow — redirect user to IdP.
     * @param provider
     * @param relayState
     * @returns any Successful Response
     * @throws ApiError
     */
    public static ssoLoginApiV1AuthSsoProviderLoginGet(
        provider: string,
        relayState?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/auth/sso/{provider}/login',
            path: {
                'provider': provider,
            },
            query: {
                'relay_state': relayState,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Sso Callback
     * Handle IdP callback. Issues an ALDECI JWT on success.
     * @param provider
     * @param code
     * @param state
     * @param formData
     * @returns CallbackResponse Successful Response
     * @throws ApiError
     */
    public static ssoCallbackApiV1AuthSsoProviderCallbackPost(
        provider: string,
        code?: (string | null),
        state?: (string | null),
        formData?: Body_sso_callback_api_v1_auth_sso__provider__callback_post,
    ): CancelablePromise<CallbackResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/auth/sso/{provider}/callback',
            path: {
                'provider': provider,
            },
            query: {
                'code': code,
                'state': state,
            },
            formData: formData,
            mediaType: 'application/x-www-form-urlencoded',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Sso Callback
     * Handle IdP callback. Issues an ALDECI JWT on success.
     * @param provider
     * @param code
     * @param state
     * @param formData
     * @returns CallbackResponse Successful Response
     * @throws ApiError
     */
    public static ssoCallbackApiV1AuthSsoProviderCallbackGet(
        provider: string,
        code?: (string | null),
        state?: (string | null),
        formData?: Body_sso_callback_api_v1_auth_sso__provider__callback_get,
    ): CancelablePromise<CallbackResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/auth/sso/{provider}/callback',
            path: {
                'provider': provider,
            },
            query: {
                'code': code,
                'state': state,
            },
            formData: formData,
            mediaType: 'application/x-www-form-urlencoded',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Saml Metadata
     * Return SAML SP metadata XML. Only valid for generic_saml provider.
     * @param provider
     * @returns any Successful Response
     * @throws ApiError
     */
    public static samlMetadataApiV1AuthSsoProviderMetadataGet(
        provider: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/auth/sso/{provider}/metadata',
            path: {
                'provider': provider,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Sso Logout
     * Single logout — invalidates the SSO session token client-side.
     *
     * Note: True SLO requires back-channel IdP communication. This endpoint
     * clears the server-side state and instructs the client to discard the token.
     * @param authorization
     * @returns LogoutResponse Successful Response
     * @throws ApiError
     */
    public static ssoLogoutApiV1AuthSsoLogoutPost(
        authorization?: (string | null),
    ): CancelablePromise<LogoutResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/auth/sso/logout',
            headers: {
                'authorization': authorization,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Sso Session
     * Return current SSO session info from a Bearer token.
     * @param authorization
     * @returns apps__api__sso_router__SessionResponse Successful Response
     * @throws ApiError
     */
    public static ssoSessionApiV1AuthSsoSessionGet(
        authorization?: (string | null),
    ): CancelablePromise<apps__api__sso_router__SessionResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/auth/sso/session',
            headers: {
                'authorization': authorization,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
