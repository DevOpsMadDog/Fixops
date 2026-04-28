/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { EventChannel } from './EventChannel';
/**
 * Body for POST /api/v1/stream/publish.
 */
export type apps__api__stream_router__PublishRequest = {
    /**
     * Target channel
     */
    channel: EventChannel;
    event_type?: string;
    data?: Record<string, any>;
    org_id?: string;
};

