/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__deception_analytics_router__CreateCampaignRequest = {
    /**
     * Campaign name
     */
    campaign_name: string;
    /**
     * early_detection | attacker_profiling | threat_intelligence | honeypot_network | insider_threat
     */
    objective?: string;
    started_at?: (string | null);
    ended_at?: (string | null);
};

