/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Impact analysis for a change.
 */
export type ImpactAnalysis = {
    affected_services?: Array<string>;
    affected_data_stores?: Array<string>;
    affected_compliance_frameworks?: Array<string>;
    /**
     * 0-10 score: how widely this change propagates
     */
    blast_radius_score?: number;
    /**
     * Change has security implications
     */
    security_impact?: boolean;
    /**
     * Change requires data migration
     */
    data_migration_required?: boolean;
    /**
     * Change affects production environment
     */
    production_impact?: boolean;
    estimated_downtime_minutes?: number;
    /**
     * Estimated number of affected users
     */
    user_impact_count?: number;
    /**
     * Linked code or service dependencies
     */
    dependency_changes?: Array<string>;
    /**
     * Computed composite risk score 0-100
     */
    risk_score?: number;
};

