/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__playbook_router__PlaybookCreateRequest } from '../models/apps__api__playbook_router__PlaybookCreateRequest';
import type { apps__api__playbook_router__PlaybookExecuteRequest } from '../models/apps__api__playbook_router__PlaybookExecuteRequest';
import type { ComplianceAssessmentResponse } from '../models/ComplianceAssessmentResponse';
import type { ComplianceControlResponse } from '../models/ComplianceControlResponse';
import type { ComplianceTemplateResponse } from '../models/ComplianceTemplateResponse';
import type { PaginatedRunsResponse } from '../models/PaginatedRunsResponse';
import type { PlaybookResponse } from '../models/PlaybookResponse';
import type { PlaybookRunResponse } from '../models/PlaybookRunResponse';
import type { PlaybookUpdateRequest } from '../models/PlaybookUpdateRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class PlaybooksService {
    /**
     * List playbooks
     * List all playbooks for an organization.
     * @param orgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listPlaybooksApiV1PlaybooksGet(
        orgId: string = 'default',
    ): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/playbooks',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Create playbook
     * Create a new security response playbook.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static createPlaybookApiV1PlaybooksPost(
        requestBody: apps__api__playbook_router__PlaybookCreateRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/playbooks',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get playbook
     * Get a specific playbook by ID.
     * @param playbookId
     * @param orgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getPlaybookApiV1PlaybooksPlaybookIdGet(
        playbookId: string,
        orgId: string = 'default',
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/playbooks/{playbook_id}',
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
     * Update Playbook
     * Update an existing playbook.
     * @param playbookId
     * @param requestBody
     * @returns PlaybookResponse Successful Response
     * @throws ApiError
     */
    public static updatePlaybookApiV1PlaybooksPlaybookIdPut(
        playbookId: string,
        requestBody: PlaybookUpdateRequest,
    ): CancelablePromise<PlaybookResponse> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/playbooks/{playbook_id}',
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
     * Execute playbook
     * Trigger execution of a playbook with optional context.
     * @param playbookId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static executePlaybookApiV1PlaybooksPlaybookIdExecutePost(
        playbookId: string,
        requestBody: apps__api__playbook_router__PlaybookExecuteRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/playbooks/{playbook_id}/execute',
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
     * Get Playbook Runs
     * Get run history for a playbook.
     * @param playbookId
     * @param limit
     * @returns PaginatedRunsResponse Successful Response
     * @throws ApiError
     */
    public static getPlaybookRunsApiV1PlaybooksPlaybookIdRunsGet(
        playbookId: string,
        limit: number = 50,
    ): CancelablePromise<PaginatedRunsResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/playbooks/{playbook_id}/runs',
            path: {
                'playbook_id': playbookId,
            },
            query: {
                'limit': limit,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Run Details
     * Get details of a specific playbook run.
     * @param runId
     * @returns PlaybookRunResponse Successful Response
     * @throws ApiError
     */
    public static getRunDetailsApiV1PlaybooksRunsRunIdGet(
        runId: string,
    ): CancelablePromise<PlaybookRunResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/playbooks/runs/{run_id}',
            path: {
                'run_id': runId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Compliance Templates
     * List all compliance templates across all frameworks.
     * @returns ComplianceTemplateResponse Successful Response
     * @throws ApiError
     */
    public static listComplianceTemplatesApiV1ComplianceTemplatesGet(): CancelablePromise<Array<ComplianceTemplateResponse>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/compliance/templates',
        });
    }
    /**
     * Get Framework Templates
     * Get all templates for a specific compliance framework.
     * @param framework
     * @returns ComplianceTemplateResponse Successful Response
     * @throws ApiError
     */
    public static getFrameworkTemplatesApiV1ComplianceTemplatesFrameworkGet(
        framework: string,
    ): CancelablePromise<Array<ComplianceTemplateResponse>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/compliance/templates/{framework}',
            path: {
                'framework': framework,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Instantiate Compliance Template
     * Create a playbook from a compliance template.
     * @param templateId
     * @returns PlaybookResponse Successful Response
     * @throws ApiError
     */
    public static instantiateComplianceTemplateApiV1ComplianceTemplatesTemplateIdInstantiatePost(
        templateId: string,
    ): CancelablePromise<PlaybookResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/compliance/templates/{template_id}/instantiate',
            path: {
                'template_id': templateId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Assess Compliance
     * Run automated compliance assessment for a framework.
     * @param framework
     * @returns ComplianceAssessmentResponse Successful Response
     * @throws ApiError
     */
    public static assessComplianceApiV1ComplianceFrameworkAssessmentGet(
        framework: string,
    ): CancelablePromise<ComplianceAssessmentResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/compliance/{framework}/assessment',
            path: {
                'framework': framework,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Framework Controls
     * Get the control catalog for a compliance framework.
     * @param framework
     * @returns ComplianceControlResponse Successful Response
     * @throws ApiError
     */
    public static getFrameworkControlsApiV1ComplianceControlsFrameworkGet(
        framework: string,
    ): CancelablePromise<Array<ComplianceControlResponse>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/compliance/controls/{framework}',
            path: {
                'framework': framework,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List execution history
     * List playbook execution history for an organization.
     * @param orgId
     * @param limit
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listExecutionsApiV1PlaybooksExecutionsGet(
        orgId: string = 'default',
        limit: number = 50,
    ): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/playbooks/executions',
            query: {
                'org_id': orgId,
                'limit': limit,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
