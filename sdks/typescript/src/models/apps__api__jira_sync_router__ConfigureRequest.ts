/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__jira_sync_router__FieldMappingItem } from './apps__api__jira_sync_router__FieldMappingItem';
/**
 * Configure the Jira sync engine.
 */
export type apps__api__jira_sync_router__ConfigureRequest = {
    /**
     * Jira base URL, e.g. https://example.atlassian.net
     */
    jira_url: string;
    /**
     * Jira user email for API auth
     */
    user_email: string;
    /**
     * Jira API token or PAT
     */
    api_token: string;
    /**
     * Jira project key, e.g. SEC
     */
    project_key: string;
    /**
     * Default Jira issue type
     */
    default_issue_type?: string;
    /**
     * bidirectional | finding_to_jira | jira_to_finding
     */
    sync_direction?: string;
    /**
     * newest_wins | jira_wins | finding_wins | manual
     */
    conflict_resolution?: string;
    labels?: Array<string>;
    /**
     * Jira component name to assign
     */
    component_name?: (string | null);
    /**
     * Secret for validating Jira webhook calls
     */
    webhook_secret?: (string | null);
    field_mappings?: Array<apps__api__jira_sync_router__FieldMappingItem>;
    /**
     * Override Jira status → finding status mapping
     */
    jira_to_finding_status?: (Record<string, string> | null);
    /**
     * Override finding status → Jira transition name mapping
     */
    finding_to_jira_transition?: (Record<string, string> | null);
    /**
     * Override severity → Jira priority mapping
     */
    severity_to_priority?: (Record<string, string> | null);
};

