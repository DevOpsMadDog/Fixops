/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AttackTreeCreate = {
    /**
     * Root attack goal
     */
    root_goal: string;
    /**
     * Attack vector
     */
    attack_vector: string;
    /**
     * critical/high/medium/low
     */
    likelihood?: string;
    /**
     * critical/high/medium/low
     */
    impact?: string;
    /**
     * Attack path steps
     */
    path_steps?: Array<string>;
};

