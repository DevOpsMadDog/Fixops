/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__soar_router__CreatePlaybookRequest } from '../models/apps__api__soar_router__CreatePlaybookRequest';
import type { apps__api__soar_router__ExecutePlaybookRequest } from '../models/apps__api__soar_router__ExecutePlaybookRequest';
import type { apps__api__soar_router__TriggerEventRequest } from '../models/apps__api__soar_router__TriggerEventRequest';
import type { MTTRResponse } from '../models/MTTRResponse';
import type { PlaybookStats } from '../models/PlaybookStats';
import type { SOARExecution } from '../models/SOARExecution';
import type { SOARPlaybook } from '../models/SOARPlaybook';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class SoarService {
    /**
     * Create a new SOAR playbook
     * Define an automated response playbook.
     *
     * The playbook will fire when an event matching `trigger` (and optional
     * `conditions`) is submitted to the /trigger endpoint.
     * @param requestBody
     * @returns SOARPlaybook Successful Response
     * @throws ApiError
     */
    public static createPlaybookApiV1SoarPlaybooksPost(
        requestBody: apps__api__soar_router__CreatePlaybookRequest,
    ): CancelablePromise<SOARPlaybook> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/soar/playbooks',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List all SOAR playbooks
     * Return all playbooks registered for the given org.
     * @param orgId Organisation ID
     * @returns SOARPlaybook Successful Response
     * @throws ApiError
     */
    public static listPlaybooksApiV1SoarPlaybooksGet(
        orgId: string = 'default',
    ): CancelablePromise<Array<SOARPlaybook>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/soar/playbooks',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get a specific SOAR playbook
     * Retrieve a playbook by its ID.
     * @param playbookId
     * @param orgId Organisation ID
     * @returns SOARPlaybook Successful Response
     * @throws ApiError
     */
    public static getPlaybookApiV1SoarPlaybooksPlaybookIdGet(
        playbookId: string,
        orgId: string = 'default',
    ): CancelablePromise<SOARPlaybook> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/soar/playbooks/{playbook_id}',
            path: {
                'playbook_id': playbookId,
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
     * Evaluate an event and fire matching playbooks
     * Submit a security event for automated response.
     *
     * Matches the event against all enabled playbooks with the given trigger type
     * and condition set. Returns execution records for every playbook that fired.
     * @param requestBody
     * @returns SOARExecution Successful Response
     * @throws ApiError
     */
    public static evaluateTriggerApiV1SoarTriggerPost(
        requestBody: apps__api__soar_router__TriggerEventRequest,
    ): CancelablePromise<Array<SOARExecution>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/soar/trigger',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Manually execute a SOAR playbook
     * Run a playbook immediately, bypassing trigger/condition evaluation.
     *
     * Useful for manual incident response or testing playbook actions.
     * Returns 404 if the playbook does not exist, 422 if it is disabled.
     * @param playbookId
     * @param requestBody
     * @returns SOARExecution Successful Response
     * @throws ApiError
     */
    public static executePlaybookApiV1SoarPlaybooksPlaybookIdExecutePost(
        playbookId: string,
        requestBody: apps__api__soar_router__ExecutePlaybookRequest,
    ): CancelablePromise<SOARExecution> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/soar/playbooks/{playbook_id}/execute',
            path: {
                'playbook_id': playbookId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get SOAR execution history
     * Return past SOAR execution records for the org.
     *
     * Optionally filter by a specific playbook ID. Results are ordered by
     * most recent first.
     * @param orgId Organisation ID
     * @param playbookId Filter by playbook ID
     * @param limit Max results
     * @returns SOARExecution Successful Response
     * @throws ApiError
     */
    public static getExecutionHistoryApiV1SoarExecutionsGet(
        orgId: string = 'default',
        playbookId?: (string | null),
        limit: number = 100,
    ): CancelablePromise<Array<SOARExecution>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/soar/executions',
            query: {
                'org_id': orgId,
                'playbook_id': playbookId,
                'limit': limit,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * SOAR playbook aggregate statistics
     * Return aggregate SOAR statistics: playbook counts, execution totals,
     * completion/failure rates, and breakdown by trigger type.
     * @param orgId Organisation ID
     * @returns PlaybookStats Successful Response
     * @throws ApiError
     */
    public static getPlaybookStatsApiV1SoarStatsGet(
        orgId: string = 'default',
    ): CancelablePromise<PlaybookStats> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/soar/stats',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Mean Time To Respond (MTTR)
     * Compute MTTR from all completed SOAR executions for the org.
     *
     * Returns seconds and minutes. Returns 0.0 if no executions have completed.
     * @param orgId Organisation ID
     * @returns MTTRResponse Successful Response
     * @throws ApiError
     */
    public static getMeanTimeToRespondApiV1SoarMttrGet(
        orgId: string = 'default',
    ): CancelablePromise<MTTRResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/soar/mttr',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
