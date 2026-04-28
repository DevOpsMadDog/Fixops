/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RegisterFeedRequest = {
    name: string;
    url: string;
    /**
     * FeedType value
     */
    type: string;
    enabled?: boolean;
    refresh_interval_minutes?: number;
    api_key?: (string | null);
};

