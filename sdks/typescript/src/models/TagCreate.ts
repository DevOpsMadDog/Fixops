/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type TagCreate = {
    /**
     * Tag key (e.g. 'env', 'team')
     */
    tag_key: string;
    /**
     * Tag value (e.g. 'production', 'security')
     */
    tag_value: string;
    /**
     * environment | criticality | data_classification | owner | compliance | technology | location | department
     */
    tag_category?: string;
    description?: string;
};

