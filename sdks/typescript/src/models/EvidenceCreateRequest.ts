/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { EvidenceType } from './EvidenceType';
export type EvidenceCreateRequest = {
    control_id: string;
    framework: string;
    type: EvidenceType;
    title: string;
    description: string;
    collected_by: string;
    file_hash?: (string | null);
    file_size?: (number | null);
    metadata?: Record<string, any>;
};

