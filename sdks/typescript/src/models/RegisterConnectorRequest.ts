/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ConnectorType } from './ConnectorType';
import type { GitHubConfig } from './GitHubConfig';
import type { JiraConfig } from './JiraConfig';
import type { SlackConfig } from './SlackConfig';
export type RegisterConnectorRequest = {
    /**
     * Unique connector name
     */
    name: string;
    /**
     * Connector type: jira, github, or slack
     */
    type: ConnectorType;
    jira?: (JiraConfig | null);
    github?: (GitHubConfig | null);
    slack?: (SlackConfig | null);
};

