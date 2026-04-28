/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request model for creating a playbook.
 */
export type apps__api__playbook_routes__PlaybookCreateRequest = {
    name: string;
    description?: string;
    trigger_conditions?: Record<string, any>;
    steps?: Array<Record<string, any>>;
    status?: string;
    tags?: Array<string>;
};

