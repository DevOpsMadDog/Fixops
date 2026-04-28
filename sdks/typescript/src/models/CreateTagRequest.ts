/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateTagRequest = {
    /**
     * Tag name
     */
    name: string;
    /**
     * Hex color code (e.g. #FF0000)
     */
    color?: string;
    /**
     * Optional description
     */
    description?: string;
    /**
     * Parent tag ID for hierarchy
     */
    parent_id?: (string | null);
    /**
     * Organisation ID
     */
    org_id?: string;
};

