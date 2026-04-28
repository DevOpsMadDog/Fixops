/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { WizardStateResponse } from '../models/WizardStateResponse';
import type { WizardStateUpdate } from '../models/WizardStateUpdate';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class AdminWizardService {
    /**
     * First-login wizard state (first GET initialises the install)
     * Return the wizard-state row, creating it on first call.
     *
     * The first GET captures ``first_seen_at`` so the FirstLoginWizard React
     * component can render exactly once for the very first admin to log in
     * on this install. Subsequent admins on the same install see no wizard
     * (because completed=true once any admin finishes it).
     * @returns WizardStateResponse Successful Response
     * @throws ApiError
     */
    public static getWizardStateApiV1AdminWizardStateGet(): CancelablePromise<WizardStateResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/admin/wizard-state',
        });
    }
    /**
     * Mark a wizard step or the whole wizard as complete
     * Append a completed step and/or mark the wizard fully done.
     *
     * Both ``step`` and ``completed`` are optional. Sending neither just returns
     * the current state (no-op). Steps are deduped on insert so the React
     * component can safely retry on network glitches.
     * @param requestBody
     * @returns WizardStateResponse Successful Response
     * @throws ApiError
     */
    public static updateWizardStateApiV1AdminWizardStatePost(
        requestBody: WizardStateUpdate,
    ): CancelablePromise<WizardStateResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/admin/wizard-state',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Reset wizard state (QA / demo / customer-success replay)
     * Clear all wizard state so the next GET starts a fresh first-login flow.
     * @returns WizardStateResponse Successful Response
     * @throws ApiError
     */
    public static resetWizardStateApiV1AdminWizardStateResetPost(): CancelablePromise<WizardStateResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/admin/wizard-state/reset',
        });
    }
}
