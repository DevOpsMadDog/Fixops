/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * A single section within an executive report.
 */
export type ReportSection = {
    /**
     * Section heading
     */
    title: string;
    /**
     * Narrative description of this section
     */
    description?: string;
    /**
     * Section data payload
     */
    data?: Record<string, any>;
    /**
     * Suggested visualization: bar, line, pie, table
     */
    chart_type?: (string | null);
    /**
     * Display order within the report (ascending)
     */
    order?: number;
};

