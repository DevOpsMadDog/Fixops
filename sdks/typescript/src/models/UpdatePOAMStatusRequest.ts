/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { POAMStatus } from './POAMStatus';
export type UpdatePOAMStatusRequest = {
    /**
     * New status
     */
    status: POAMStatus;
    /**
     * Set true to mark the risk as formally accepted
     */
    risk_accepted?: boolean;
};

