/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__container_registry_security_router__CreatePolicyRequest = {
    /**
     * Policy name
     */
    name: string;
    /**
     * Block images with any critical CVEs
     */
    block_critical?: boolean;
    /**
     * Maximum allowed high-severity CVEs
     */
    max_high_vulns?: number;
    /**
     * Require image signature verification
     */
    require_signed?: boolean;
};

