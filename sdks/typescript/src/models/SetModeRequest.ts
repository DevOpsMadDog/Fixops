/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { RaspMode } from './RaspMode';
/**
 * Body for switching RASP operating mode.
 */
export type SetModeRequest = {
    /**
     * New operating mode: monitor | block | redirect
     */
    mode: RaspMode;
    /**
     * Honeypot redirect URL (required when mode=redirect)
     */
    honeypot_url?: (string | null);
};

