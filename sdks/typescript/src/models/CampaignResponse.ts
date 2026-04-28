/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * API response for a phishing campaign.
 */
export type CampaignResponse = {
    id: string;
    name: string;
    template_id: string;
    target_emails: Array<string>;
    sent_count: number;
    opened_count: number;
    clicked_count: number;
    reported_count: number;
    started_at: string;
    ended_at: (string | null);
    org_id: string;
};

