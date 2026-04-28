/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type FeedCreate = {
    feed_name: string;
    feed_type?: string;
    url?: string;
    api_key?: string;
    format?: string;
    status?: string;
    poll_interval_minutes?: number;
    ioc_count?: number;
    last_polled?: (string | null);
};

