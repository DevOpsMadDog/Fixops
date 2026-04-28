/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateCardRequest = {
    /**
     * ID of the security finding
     */
    finding_id: string;
    /**
     * Short card title
     */
    title: string;
    /**
     * Full description of what needs fixing
     */
    description?: string;
    /**
     * Assignee email or username
     */
    assignee?: (string | null);
    /**
     * critical|high|medium|low|informational
     */
    priority?: string;
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Optional labels/tags
     */
    labels?: Array<string>;
    /**
     * ISO 8601 due date, e.g. 2026-05-01T00:00:00Z
     */
    due_date?: (string | null);
};

