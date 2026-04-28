/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { Channel } from './Channel';
import type { DigestFrequency } from './DigestFrequency';
export type UpdatePreferenceRequest = {
    channels?: (Array<Channel> | null);
    digest_frequency?: (DigestFrequency | null);
    muted_sources?: (Array<string> | null);
    quiet_hours_start?: (number | null);
    quiet_hours_end?: (number | null);
};

