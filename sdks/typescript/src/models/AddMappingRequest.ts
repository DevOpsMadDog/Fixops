/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AddMappingRequest = {
    /**
     * Source control identifier
     */
    source_control_id: string;
    /**
     * Target control identifier
     */
    target_control_id: string;
    /**
     * Source framework key
     */
    source_framework: string;
    /**
     * Target framework key
     */
    target_framework: string;
    /**
     * strong | moderate | weak
     */
    mapping_strength: string;
    notes?: (string | null);
};

