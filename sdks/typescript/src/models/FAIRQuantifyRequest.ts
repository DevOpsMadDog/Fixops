/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * POST /api/v1/risk/quantify-fair body — accepts either an existing
 * scenario_id (re-quantify) or finding-derived parameters (quantify_finding).
 */
export type FAIRQuantifyRequest = {
    /**
     * Existing scenario id to quantify
     */
    scenario_id?: (string | null);
    /**
     * Finding payload to derive parameters from (severity, asset_type, ...)
     */
    finding?: (Record<string, any> | null);
};

