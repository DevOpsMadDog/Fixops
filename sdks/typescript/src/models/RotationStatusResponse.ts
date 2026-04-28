/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response for /rotation-status endpoint.
 */
export type RotationStatusResponse = {
    org_id: string;
    total: number;
    active: number;
    rotated: number;
    false_positive: number;
    rotation_rate: number;
};

