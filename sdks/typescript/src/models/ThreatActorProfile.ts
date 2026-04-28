/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ThreatActorMotivation } from './ThreatActorMotivation';
/**
 * A known threat actor profile.
 */
export type ThreatActorProfile = {
    id?: string;
    name: string;
    aliases?: Array<string>;
    motivation?: ThreatActorMotivation;
    description?: string;
    targeted_industries?: Array<string>;
    targeted_regions?: Array<string>;
    mitre_techniques?: Array<string>;
    associated_ioc_ids?: Array<string>;
    first_observed?: (string | null);
    last_active?: (string | null);
    sophistication?: string;
    tags?: Array<string>;
    created_at?: string;
};

