/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class PlatformHealthService {
    /**
     * Platform health dashboard — comprehensive at-a-glance snapshot
     * Return a single comprehensive platform health snapshot.
     *
     * Aggregates:
     * - Engine health (total / healthy / degraded)
     * - Router coverage (total / mounted)
     * - Frontend page wiring (pages / wired to API)
     * - Test suite totals and Beast Mode passing count
     * - Live data counts (brain nodes, alerts, vulns, assets, compliance frameworks)
     * - Feed status (active / configured)
     * - TrustGraph wiring stats
     * - Intelligence mesh status
     * @returns any Successful Response
     * @throws ApiError
     */
    public static platformHealthApiV1PlatformHealthGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/platform/health',
        });
    }
}
