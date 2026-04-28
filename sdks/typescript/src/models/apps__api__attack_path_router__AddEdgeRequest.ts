/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__attack_path_router__AddEdgeRequest = {
    /**
     * Source node ID
     */
    from_node: string;
    /**
     * Destination node ID
     */
    to_node: string;
    /**
     * Network protocol
     */
    protocol?: string;
    /**
     * Network port (0 = any)
     */
    port?: number;
    /**
     * CVE ID required to traverse this edge
     */
    requires_vuln?: (string | null);
    /**
     * Organisation ID
     */
    org_id?: string;
};

