/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__connectors_router__FindingInput } from './apps__api__connectors_router__FindingInput';
export type CreateTicketRequest = {
    finding: apps__api__connectors_router__FindingInput;
    /**
     * Specific connector names to target; null = all
     */
    targets?: (Array<string> | null);
};

