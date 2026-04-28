/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__attack_path_router__AddNodeRequest = {
    /**
     * Unique node identifier (e.g. hostname or IP)
     */
    node_id: string;
    /**
     * Node type: workstation|server|database|cloud_service|network_device|external
     */
    node_type: string;
    /**
     * Human-readable node name
     */
    name: string;
    /**
     * Risk score 0-100
     */
    risk_score?: number;
    /**
     * Whether this node is a crown jewel asset
     */
    is_crown_jewel?: boolean;
    /**
     * CVE IDs present on this node
     */
    vulnerabilities?: Array<string>;
    /**
     * Organisation ID
     */
    org_id?: string;
};

