/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Body for POST /api/v1/admin/wizard-state.
 */
export type WizardStateUpdate = {
    /**
     * Wizard step just completed (e.g. 'create_org'). Appended idempotently.
     */
    step?: (string | null);
    /**
     * Set true to mark the whole wizard complete (sets completed_at).
     */
    completed?: (boolean | null);
};

