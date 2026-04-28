/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { api__mitre_mapper_router__FindingInput } from './api__mitre_mapper_router__FindingInput';
/**
 * Request for kill chain coverage analysis.
 */
export type KillChainRequest = {
    /**
     * Security findings for kill chain analysis
     */
    findings: Array<api__mitre_mapper_router__FindingInput>;
};

