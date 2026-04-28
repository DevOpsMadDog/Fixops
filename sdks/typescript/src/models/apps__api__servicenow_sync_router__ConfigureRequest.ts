/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__servicenow_sync_router__FieldMappingItem } from './apps__api__servicenow_sync_router__FieldMappingItem';
/**
 * Configure the ServiceNow sync engine.
 */
export type apps__api__servicenow_sync_router__ConfigureRequest = {
    /**
     * ServiceNow instance URL, e.g. https://mycompany.service-now.com
     */
    instance_url: string;
    /**
     * ServiceNow username for basic auth
     */
    username: string;
    /**
     * ServiceNow password or API token
     */
    password: string;
    /**
     * ServiceNow assignment group name for created incidents
     */
    assignment_group?: string;
    /**
     * Incident category
     */
    category?: string;
    /**
     * Incident subcategory
     */
    subcategory?: string;
    /**
     * bidirectional | finding_to_servicenow | servicenow_to_finding
     */
    sync_direction?: string;
    /**
     * newest_wins | servicenow_wins | finding_wins | manual
     */
    conflict_resolution?: string;
    tags?: Array<string>;
    /**
     * Secret for validating ServiceNow webhook calls
     */
    webhook_secret?: (string | null);
    field_mappings?: Array<apps__api__servicenow_sync_router__FieldMappingItem>;
    /**
     * Override ServiceNow state → finding status mapping
     */
    sn_state_to_finding_status?: (Record<string, string> | null);
    /**
     * Override finding status → ServiceNow state code mapping
     */
    finding_to_sn_state?: (Record<string, string> | null);
    /**
     * Override severity → ServiceNow urgency mapping
     */
    severity_to_urgency?: (Record<string, string> | null);
    /**
     * Override severity → ServiceNow impact mapping
     */
    severity_to_impact?: (Record<string, string> | null);
};

