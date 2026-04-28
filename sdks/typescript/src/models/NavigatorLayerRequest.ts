/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { api__mitre_mapper_router__FindingInput } from './api__mitre_mapper_router__FindingInput';
/**
 * Request to generate a MITRE ATT&CK Navigator layer JSON.
 */
export type NavigatorLayerRequest = {
    /**
     * Security findings to include in the Navigator layer
     */
    findings: Array<api__mitre_mapper_router__FindingInput>;
    /**
     * Display name for the ATT&CK Navigator layer
     */
    layer_name?: string;
    /**
     * Layer description
     */
    description?: string;
};

