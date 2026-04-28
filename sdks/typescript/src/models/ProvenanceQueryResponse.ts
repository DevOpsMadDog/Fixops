/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ProvenanceRecord } from './ProvenanceRecord';
/**
 * Response for a provenance lookup.
 */
export type ProvenanceQueryResponse = {
    found: boolean;
    component_name: string;
    component_version: (string | null);
    provenance: (ProvenanceRecord | null);
};

