/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__openclaw_router__CampaignCreate = {
    name: string;
    description?: string;
    /**
     * network_pentest|web_app|cloud_security|social_engineering|physical_access|full_red_team
     */
    campaign_type?: string;
    target_scope?: Array<string>;
    attack_tactics?: Array<string>;
    operators_count?: number;
    /**
     * Required authorization token confirming written approval for this pentest
     */
    authorization_token: string;
    authorized_by?: string;
    authorized_until?: string;
};

