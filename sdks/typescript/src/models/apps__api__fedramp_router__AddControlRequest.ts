/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ControlFamily } from './ControlFamily';
import type { ControlStatus } from './ControlStatus';
import type { FedRAMPBaseline } from './FedRAMPBaseline';
/**
 * Request body for adding a custom control.
 */
export type apps__api__fedramp_router__AddControlRequest = {
    /**
     * Control identifier, e.g. AC-99
     */
    id: string;
    family: ControlFamily;
    title: string;
    description: string;
    baseline?: Array<FedRAMPBaseline>;
    status?: ControlStatus;
    evidence_ids?: Array<string>;
    implementation_notes?: string;
};

