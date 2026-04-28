/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type PBOMRecordStepRequest = {
    /**
     * Pipeline run DB id
     */
    run_id: string;
    step_order: number;
    step_name: string;
    /**
     * build|test|lint|scan|sign|publish|deploy
     */
    step_type: string;
    image?: string;
    command?: string;
    config_hash?: string;
    duration_ms?: number;
    outcome?: string;
};

