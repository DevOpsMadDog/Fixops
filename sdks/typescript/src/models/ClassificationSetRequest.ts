/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for setting the classification level.
 */
export type ClassificationSetRequest = {
    /**
     * Classification level: UNCLASSIFIED | CUI | SECRET | TOP SECRET
     */
    level: string;
    /**
     * Identity of the operator setting classification
     */
    set_by?: string;
};

