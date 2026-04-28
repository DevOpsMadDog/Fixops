/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for POST /evidence/export — signed compliance bundle.
 */
export type api__evidence_router__ExportRequest = {
    /**
     * Compliance framework for control mapping
     */
    framework?: string;
    /**
     * Optional APP_ID scope
     */
    app_id?: string;
    /**
     * Assessment period in days
     */
    period_days?: number;
    /**
     * Include evidence items per control
     */
    include_evidence?: boolean;
    /**
     * Sign the bundle with RSA-SHA256
     */
    sign?: boolean;
};

