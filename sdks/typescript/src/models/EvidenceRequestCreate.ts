/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type EvidenceRequestCreate = {
    /**
     * SOC2 | ISO27001 | PCI-DSS | HIPAA
     */
    framework?: string;
    /**
     * Control identifier
     */
    control_id?: string;
    /**
     * Human-readable control name
     */
    control_name?: string;
    /**
     * What evidence is needed
     */
    description?: string;
    /**
     * ISO date string
     */
    due_date?: string;
    /**
     * Who is responsible
     */
    assignee?: string;
};

