/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__wave_a_code_intel_router__CallGraphRequest } from '../models/apps__api__wave_a_code_intel_router__CallGraphRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class WaveAReachabilityService {
    /**
     * Build a callgraph for a repo
     * Build a callgraph for a repo using the function_reachability_engine.
     *
     * For Python repos with a local ``repo_path`` provided we delegate to the
     * engine's AST parser. For non-Python or remote repos, returns 501.
     * @param requestBody
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static reachabilityCallgraphApiV1ReachabilityCallgraphPost(
        requestBody: apps__api__wave_a_code_intel_router__CallGraphRequest,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/reachability/callgraph',
            headers: {
                'X-Org-ID': xOrgId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Return reachability proof / verdict for a finding
     * Return the reachability verdict (path) for a finding.
     *
     * Wraps ``FunctionReachabilityEngine.get_finding_verdict``.
     * Returns 404 if no verdict has been computed.
     * @param findingId
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static reachabilityProofApiV1ReachabilityFindingIdProofGet(
        findingId: string,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/reachability/{finding_id}/proof',
            path: {
                'finding_id': findingId,
            },
            headers: {
                'X-Org-ID': xOrgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
