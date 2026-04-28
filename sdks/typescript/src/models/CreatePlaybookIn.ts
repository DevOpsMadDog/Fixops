/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreatePlaybookIn = {
    /**
     * Playbook name
     */
    playbook_name: string;
    /**
     * Ordered list of playbook steps
     */
    steps?: Array<any>;
    /**
     * host|container|network|identity|application|cloud_resource
     */
    target_type?: string;
    /**
     * Estimated run time in minutes
     */
    estimated_duration_minutes?: number;
};

