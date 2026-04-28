/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CreateControlRequest } from '../models/CreateControlRequest';
import type { CreateKRIRequest } from '../models/CreateKRIRequest';
import type { CreateRiskRequest } from '../models/CreateRiskRequest';
import type { CreateTreatmentRequest } from '../models/CreateTreatmentRequest';
import type { MapControlRequest } from '../models/MapControlRequest';
import type { SetAppetiteRequest } from '../models/SetAppetiteRequest';
import type { UpdateKRIValueRequest } from '../models/UpdateKRIValueRequest';
import type { UpdateRiskRequest } from '../models/UpdateRiskRequest';
import type { UpdateTreatmentStatusRequest } from '../models/UpdateTreatmentStatusRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class RiskRegisterService {
    /**
     * Create a risk
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static createRiskApiV1RisksPost(
        requestBody: CreateRiskRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/risks',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List risks
     * @param orgId
     * @param category
     * @param status
     * @param minScore
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listRisksApiV1RisksGet(
        orgId: string = 'default',
        category?: (string | null),
        status?: (string | null),
        minScore?: (number | null),
    ): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/risks',
            query: {
                'org_id': orgId,
                'category': category,
                'status': status,
                'min_score': minScore,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Create a control
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static createControlApiV1RisksControlsPost(
        requestBody: CreateControlRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/risks/controls',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List controls
     * @param orgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listControlsApiV1RisksControlsListGet(
        orgId: string = 'default',
    ): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/risks/controls/list',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Create a treatment plan
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static createTreatmentApiV1RisksTreatmentsPost(
        requestBody: CreateTreatmentRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/risks/treatments',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Update treatment plan status
     * @param planId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static updateTreatmentStatusApiV1RisksTreatmentsPlanIdStatusPatch(
        planId: string,
        requestBody: UpdateTreatmentStatusRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'PATCH',
            url: '/api/v1/risks/treatments/{plan_id}/status',
            path: {
                'plan_id': planId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Create a KRI
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static createKriApiV1RisksKrisPost(
        requestBody: CreateKRIRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/risks/kris',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List KRIs
     * @param orgId
     * @param riskId
     * @param status
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listKrisApiV1RisksKrisListGet(
        orgId: string = 'default',
        riskId?: (string | null),
        status?: (string | null),
    ): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/risks/kris/list',
            query: {
                'org_id': orgId,
                'risk_id': riskId,
                'status': status,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Update KRI current value
     * @param kriId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static updateKriValueApiV1RisksKrisKriIdValuePatch(
        kriId: string,
        requestBody: UpdateKRIValueRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'PATCH',
            url: '/api/v1/risks/kris/{kri_id}/value',
            path: {
                'kri_id': kriId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Set risk appetite for a category
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static setAppetiteApiV1RisksAppetitePost(
        requestBody: SetAppetiteRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/risks/appetite',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List risk appetites
     * @param orgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listAppetitesApiV1RisksAppetiteListGet(
        orgId: string = 'default',
    ): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/risks/appetite/list',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get risk heat map data
     * @param orgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getHeatMapApiV1RisksHeatmapGet(
        orgId: string = 'default',
    ): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/risks/heatmap',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Board-level risk report
     * @param orgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static boardReportApiV1RisksReportBoardGet(
        orgId: string = 'default',
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/risks/report/board',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get a risk
     * @param riskId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getRiskApiV1RisksRiskIdGet(
        riskId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/risks/{risk_id}',
            path: {
                'risk_id': riskId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Update a risk
     * @param riskId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static updateRiskApiV1RisksRiskIdPatch(
        riskId: string,
        requestBody: UpdateRiskRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'PATCH',
            url: '/api/v1/risks/{risk_id}',
            path: {
                'risk_id': riskId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Delete a risk
     * @param riskId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static deleteRiskApiV1RisksRiskIdDelete(
        riskId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/v1/risks/{risk_id}',
            path: {
                'risk_id': riskId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Map a control to a risk
     * @param riskId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static mapControlApiV1RisksRiskIdControlsMapPost(
        riskId: string,
        requestBody: MapControlRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/risks/{risk_id}/controls/map',
            path: {
                'risk_id': riskId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Unmap a control from a risk
     * @param riskId
     * @param ctrlId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static unmapControlApiV1RisksRiskIdControlsCtrlIdDelete(
        riskId: string,
        ctrlId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/v1/risks/{risk_id}/controls/{ctrl_id}',
            path: {
                'risk_id': riskId,
                'ctrl_id': ctrlId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List treatment plans for a risk
     * @param riskId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listTreatmentsApiV1RisksRiskIdTreatmentsGet(
        riskId: string,
    ): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/risks/{risk_id}/treatments',
            path: {
                'risk_id': riskId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
