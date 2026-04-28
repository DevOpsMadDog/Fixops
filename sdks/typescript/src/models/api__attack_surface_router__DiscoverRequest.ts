/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type api__attack_surface_router__DiscoverRequest = {
    /**
     * Target domain to discover
     */
    domain: string;
    /**
     * Scan for open ports
     */
    scan_ports?: boolean;
    /**
     * Check TLS certificates
     */
    check_certs?: boolean;
    /**
     * Enumerate subdomains
     */
    enumerate_subdomains?: boolean;
    /**
     * Port scan timeout in seconds
     */
    port_timeout?: number;
};

