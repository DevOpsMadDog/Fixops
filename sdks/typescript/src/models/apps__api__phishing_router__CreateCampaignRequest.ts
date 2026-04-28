/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for launching a phishing campaign.
 */
export type apps__api__phishing_router__CreateCampaignRequest = {
    /**
     * Display name for the campaign
     */
    name: string;
    /**
     * ID of the phishing template to use
     */
    template_id: string;
    /**
     * Employee email addresses to target
     */
    target_emails: Array<string>;
    /**
     * Organisation identifier
     */
    org_id: string;
};

