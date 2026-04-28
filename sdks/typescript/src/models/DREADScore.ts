/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * DREAD risk scoring model.
 *
 * Each dimension rated 1–10 (1 = lowest risk, 10 = highest).
 * ``total`` is the arithmetic mean of all five dimensions.
 */
export type DREADScore = {
    /**
     * Damage potential if exploited (1-10)
     */
    damage: number;
    /**
     * How easily can the attack be reproduced (1-10)
     */
    reproducibility: number;
    /**
     * Skill/effort required to exploit (1-10)
     */
    exploitability: number;
    /**
     * Number of users affected (1-10)
     */
    affected_users: number;
    /**
     * How easy is it to discover the vulnerability (1-10)
     */
    discoverability: number;
    /**
     * Computed mean of all five dimensions
     */
    total?: number;
};

