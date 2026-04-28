/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { TimelineEventOut } from './TimelineEventOut';
export type ForensicTimelineOut = {
    query: string;
    start: string;
    end: string;
    total: number;
    actors: Array<string>;
    resources: Array<string>;
    events: Array<TimelineEventOut>;
};

