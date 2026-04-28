/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type StepRequest = {
    /**
     * Ordinal of this step in the run
     */
    step_order: number;
    /**
     * Human-readable step name
     */
    step_name: string;
    /**
     * build|test|lint|scan|sign|publish|deploy
     */
    step_type: string;
    /**
     * Container image used to run the step
     */
    image?: string;
    /**
     * Command executed by the step
     */
    command?: string;
    /**
     * Hash of step config (YAML/JSON)
     */
    config_hash?: string;
    duration_ms?: number;
    /**
     * success|failed|skipped|cancelled|neutral
     */
    outcome?: string;
};

