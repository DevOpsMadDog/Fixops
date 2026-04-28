/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type EnhancedDecisionRequest = {
    /**
     * Primary service or application identifier
     */
    service_name: string;
    /**
     * Deployment environment
     */
    environment?: string;
    business_context?: Record<string, any>;
    security_findings?: Array<Record<string, any>>;
    compliance_requirements?: Array<string>;
    cnapp?: (Record<string, any> | null);
    exploitability?: (Record<string, any> | null);
    ai_agent_analysis?: (Record<string, any> | null);
    marketplace_recommendations?: null;
};

