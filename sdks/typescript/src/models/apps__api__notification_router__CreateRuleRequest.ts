/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { Channel } from './Channel';
import type { DigestFrequency } from './DigestFrequency';
export type apps__api__notification_router__CreateRuleRequest = {
    name: string;
    description?: (string | null);
    enabled?: boolean;
    conditions?: Record<string, any>;
    channels?: Array<Channel>;
    recipients?: Array<string>;
    digest_frequency?: DigestFrequency;
};

