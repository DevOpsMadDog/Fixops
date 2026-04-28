/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__cloud_graph_router__AddNodeRequest = {
    /**
     * NodeType value
     */
    type: string;
    /**
     * Resource name
     */
    name: string;
    /**
     * Cloud provider
     */
    provider?: string;
    /**
     * Cloud region
     */
    region?: string;
    /**
     * Resource config dict
     */
    config?: Record<string, any>;
    /**
     * Risk score 0-1
     */
    risk_score?: number;
    /**
     * Known CVEs/issues
     */
    vulnerabilities?: Array<string>;
    /**
     * Internet-reachable?
     */
    public?: boolean;
    /**
     * Organisation ID
     */
    org_id?: string;
};

