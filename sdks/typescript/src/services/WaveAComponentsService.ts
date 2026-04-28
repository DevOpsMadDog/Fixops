/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class WaveAComponentsService {
    /**
     * Match SBOM components by Application Binary Fingerprint
     * Search SBOM component records for a given ABF (binary hash).
     *
     * Uses ``SBOMEngine`` storage. Falls back to scanning persistent_store ABF
     * entries if the engine has no `list_components_by_hash` API.
     * @param abf ABF — usually a sha256 of binary contents
     * @param orgId
     * @param limit
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static componentsMatchByAbfApiV1ComponentsMatchByAbfGet(
        abf: string,
        orgId: string = 'default',
        limit: number = 50,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/components/match-by-abf',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'abf': abf,
                'org_id': orgId,
                'limit': limit,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Resolve safe upgrade target for a component PURL
     * Resolve the next safe upgrade target for a component.
     *
     * Wraps ``UpgradePathResolverEngine.resolve_upgrade(org_id, purl, cve_ids)``.
     *
     * The engine signature requires a non-empty ``cve_ids`` list — when no CVEs
     * are supplied we attempt to derive them from the engine's per-package vuln
     * catalogue, falling back to a 422 if there are none.
     * @param purl
     * @param currentVersion
     * @param cveIds Comma-separated CVE IDs
     * @param orgId
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static componentsSafeUpgradeApiV1ComponentsPurlSafeUpgradeGet(
        purl: string,
        currentVersion?: (string | null),
        cveIds?: (string | null),
        orgId: string = 'default',
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/components/{purl}/safe-upgrade',
            path: {
                'purl': purl,
            },
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'current_version': currentVersion,
                'cve_ids': cveIds,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
