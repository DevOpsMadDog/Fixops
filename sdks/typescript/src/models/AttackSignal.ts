/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AttackType } from './AttackType';
import type { core__supply_chain_security__RiskLevel } from './core__supply_chain_security__RiskLevel';
/**
 * A detected supply chain attack signal.
 */
export type AttackSignal = {
    id?: string;
    attack_type: AttackType;
    severity?: core__supply_chain_security__RiskLevel;
    component_name: string;
    component_version: string;
    description: string;
    evidence?: Record<string, any>;
    /**
     * For typosquatting: the real package
     */
    similar_package?: (string | null);
    confidence?: number;
    detected_at?: string;
    org_id?: string;
};

