/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CaseIn } from '../models/CaseIn';
import type { CloseIn } from '../models/CloseIn';
import type { EvidenceIn } from '../models/EvidenceIn';
import type { SealIn } from '../models/SealIn';
import type { TransferIn } from '../models/TransferIn';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class EvidenceChainService {
    /**
     * List Cases
     * List all investigation cases for an org.
     * @param orgId
     * @param status
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listCasesApiV1EvidenceChainCasesGet(
        orgId: string = 'default',
        status?: (string | null),
    ): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/evidence-chain/cases',
            query: {
                'org_id': orgId,
                'status': status,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Create Case
     * Create a new investigation case.
     * @param requestBody
     * @param orgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static createCaseApiV1EvidenceChainCasesPost(
        requestBody: CaseIn,
        orgId: string = 'default',
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/evidence-chain/cases',
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
     * Get Case
     * Get a single investigation case.
     * @param caseId
     * @param orgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getCaseApiV1EvidenceChainCasesCaseIdGet(
        caseId: string,
        orgId: string = 'default',
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/evidence-chain/cases/{case_id}',
            path: {
                'case_id': caseId,
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
     * Close Case
     * Close a case with outcome.
     * @param caseId
     * @param requestBody
     * @param orgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static closeCaseApiV1EvidenceChainCasesCaseIdClosePost(
        caseId: string,
        requestBody: CloseIn,
        orgId: string = 'default',
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/evidence-chain/cases/{case_id}/close',
            path: {
                'case_id': caseId,
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
     * List Evidence
     * List all evidence items for a case.
     * @param caseId
     * @param orgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listEvidenceApiV1EvidenceChainCasesCaseIdEvidenceGet(
        caseId: string,
        orgId: string = 'default',
    ): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/evidence-chain/cases/{case_id}/evidence',
            path: {
                'case_id': caseId,
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
     * Add Evidence
     * Add an evidence item to a case.
     * @param caseId
     * @param requestBody
     * @param orgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static addEvidenceApiV1EvidenceChainCasesCaseIdEvidencePost(
        caseId: string,
        requestBody: EvidenceIn,
        orgId: string = 'default',
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/evidence-chain/cases/{case_id}/evidence',
            path: {
                'case_id': caseId,
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
     * Get Custody Chain
     * Get the complete chain of custody for an evidence item.
     * @param evidenceId
     * @param orgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getCustodyChainApiV1EvidenceChainEvidenceEvidenceIdCustodyGet(
        evidenceId: string,
        orgId: string = 'default',
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/evidence-chain/evidence/{evidence_id}/custody',
            path: {
                'evidence_id': evidenceId,
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
     * Transfer Custody
     * Record a custody transfer for an evidence item.
     * @param evidenceId
     * @param requestBody
     * @param orgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static transferCustodyApiV1EvidenceChainEvidenceEvidenceIdCustodyPost(
        evidenceId: string,
        requestBody: TransferIn,
        orgId: string = 'default',
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/evidence-chain/evidence/{evidence_id}/custody',
            path: {
                'evidence_id': evidenceId,
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
     * Seal Evidence
     * Seal evidence to prevent further custody transfers.
     * @param evidenceId
     * @param requestBody
     * @param orgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static sealEvidenceApiV1EvidenceChainEvidenceEvidenceIdSealPost(
        evidenceId: string,
        requestBody: SealIn,
        orgId: string = 'default',
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/evidence-chain/evidence/{evidence_id}/seal',
            path: {
                'evidence_id': evidenceId,
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
     * Verify Integrity
     * Verify hash consistency and chain integrity for an evidence item.
     * @param evidenceId
     * @param orgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static verifyIntegrityApiV1EvidenceChainEvidenceEvidenceIdVerifyGet(
        evidenceId: string,
        orgId: string = 'default',
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/evidence-chain/evidence/{evidence_id}/verify',
            path: {
                'evidence_id': evidenceId,
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
     * Get Stats
     * Return evidence statistics for an org.
     * @param orgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getStatsApiV1EvidenceChainStatsGet(
        orgId: string = 'default',
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/evidence-chain/stats',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
