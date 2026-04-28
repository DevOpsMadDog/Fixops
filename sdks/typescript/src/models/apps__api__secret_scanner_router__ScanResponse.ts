/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { DetectedSecret } from './DetectedSecret';
/**
 * Response for /scan endpoint.
 */
export type apps__api__secret_scanner_router__ScanResponse = {
    secrets_found: number;
    secrets: Array<DetectedSecret>;
};

