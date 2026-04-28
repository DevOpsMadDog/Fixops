/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Per-IP attacker summary.
 */
export type AttackerStats = {
    ip: string;
    total_threats: number;
    categories: Record<string, number>;
    first_seen: string;
    last_seen: string;
    is_blocked: boolean;
    block_expires_at?: (string | null);
};

