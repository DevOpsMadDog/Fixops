/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__container_security_connector_router__ScanRequest = {
    /**
     * Tenant id (directory name under tenants_root). Omit to scan all.
     */
    tenant?: (string | null);
    /**
     * Override default tenants root (defaults to /tmp/aspm-repos).
     */
    tenants_root?: (string | null);
    /**
     * Image tag prefix, default 'fixops-test'.
     */
    image_prefix?: (string | null);
    /**
     * Also run kube-bench against the currently-active cluster.
     */
    run_kubebench?: boolean;
};

