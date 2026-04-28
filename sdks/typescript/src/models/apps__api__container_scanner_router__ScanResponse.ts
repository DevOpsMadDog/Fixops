/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__container_scanner_router__FindingSummary } from './apps__api__container_scanner_router__FindingSummary';
export type apps__api__container_scanner_router__ScanResponse = {
    id: string;
    file_path: string;
    base_image: string;
    user: string;
    exposed_ports: Array<number>;
    total_layers: number;
    score: number;
    org_id: string;
    findings_count: number;
    findings: Array<apps__api__container_scanner_router__FindingSummary>;
    scanned_at: string;
};

