/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { TriageQueueItem } from './TriageQueueItem';
/**
 * Response for /queue.
 */
export type TriageQueueResponse = {
    queue: Array<TriageQueueItem>;
    total: number;
    buckets: Record<string, number>;
    timestamp: string;
};

