/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AddSegmentRequest = {
    name: string;
    cidr?: string;
    /**
     * dmz/internal/cloud/ot/guest
     */
    segment_type?: string;
    /**
     * critical/high/medium/low
     */
    sensitivity?: string;
};

