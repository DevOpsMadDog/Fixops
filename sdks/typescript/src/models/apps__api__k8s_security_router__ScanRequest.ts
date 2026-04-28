/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__k8s_security_router__ScanRequest = {
    /**
     * Logical cluster name
     */
    cluster_name?: string;
    /**
     * Path to kubeconfig file
     */
    kubeconfig_path?: (string | null);
    /**
     * Use in-cluster service account credentials
     */
    in_cluster?: boolean;
    /**
     * kubeconfig context to use
     */
    context?: (string | null);
    /**
     * Namespaces to scan (empty = all)
     */
    namespaces?: Array<string>;
    /**
     * Trusted image registries (overrides engine defaults if non-empty)
     */
    trusted_registries?: Array<string>;
    /**
     * Raw Kubernetes resource dicts (for offline/testing mode)
     */
    resources?: Array<Record<string, any>>;
    /**
     * Raw RBAC resource dicts (Role, ClusterRole, RoleBinding, ClusterRoleBinding)
     */
    rbac_resources?: Array<Record<string, any>>;
    /**
     * Raw NetworkPolicy resource dicts
     */
    network_policies?: Array<Record<string, any>>;
};

