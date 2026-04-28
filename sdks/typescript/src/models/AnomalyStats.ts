/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Summary of anomalies for an org.
 */
export type AnomalyStats = {
    org_id: string;
    total: number;
    by_type: Record<string, number>;
    by_severity: Record<string, number>;
    unacknowledged: number;
    oldest_unacked: (string | null);
    newest: (string | null);
};

