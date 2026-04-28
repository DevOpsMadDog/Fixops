/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__connector_routes__FindingSeverity } from './apps__api__connector_routes__FindingSeverity';
/**
 * Finding ready for export to external system.
 */
export type FindingForExport = {
    /**
     * ALDECI finding ID
     */
    finding_id: string;
    /**
     * Original connector source
     */
    source: string;
    /**
     * Finding title
     */
    title: string;
    /**
     * Severity level
     */
    severity: apps__api__connector_routes__FindingSeverity;
    /**
     * Description
     */
    description?: (string | null);
    /**
     * Remediation guidance
     */
    remediation?: (string | null);
    /**
     * IDs in external systems (e.g. {'jira': 'PROJ-123'})
     */
    external_ids?: Record<string, string>;
    /**
     * Additional metadata
     */
    metadata?: Record<string, any>;
};

