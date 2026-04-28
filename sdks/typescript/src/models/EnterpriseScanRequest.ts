/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { api__micro_pentest_router__AttackSurfaceRequest } from './api__micro_pentest_router__AttackSurfaceRequest';
import type { ThreatModelRequest } from './ThreatModelRequest';
/**
 * Request model for enterprise micro penetration test scan.
 */
export type EnterpriseScanRequest = {
    /**
     * Name of the scan
     */
    name: string;
    /**
     * Attack surface
     */
    attack_surface: api__micro_pentest_router__AttackSurfaceRequest;
    /**
     * Threat model
     */
    threat_model: ThreatModelRequest;
    /**
     * Scan mode
     */
    scan_mode?: string;
    /**
     * Timeout
     */
    timeout_seconds?: number;
    /**
     * Stop on critical finding
     */
    stop_on_critical?: boolean;
    /**
     * Include PoC
     */
    include_proof_of_concept?: boolean;
    /**
     * Tenant ID
     */
    tenant_id?: string;
    /**
     * Organization ID
     */
    organization_id?: string;
    /**
     * Tags
     */
    tags?: Array<string>;
};

