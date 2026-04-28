/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { Channel } from './Channel';
import type { DigestFrequency } from './DigestFrequency';
export type apps__api__notification_router__UpdateRuleRequest = {
    name?: (string | null);
    description?: (string | null);
    enabled?: (boolean | null);
    conditions?: (Record<string, any> | null);
    channels?: (Array<Channel> | null);
    recipients?: (Array<string> | null);
    digest_frequency?: (DigestFrequency | null);
};

