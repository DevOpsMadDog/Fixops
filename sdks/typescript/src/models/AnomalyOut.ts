/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Serialisable anomaly record.
 */
export type AnomalyOut = {
    id: string;
    org_id: string;
    kind: string;
    severity: string;
    actor: string;
    description: string;
    entry_ids: Array<string>;
    detected_at: string;
    details?: Record<string, any>;
};

