/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { api__mitre_mapper_router__FindingInput } from './api__mitre_mapper_router__FindingInput';
/**
 * Request to map a list of findings to MITRE ATT&CK techniques.
 */
export type api__mitre_mapper_router__MapFindingsRequest = {
    /**
     * List of security findings to map (max 500)
     */
    findings: Array<api__mitre_mapper_router__FindingInput>;
};

