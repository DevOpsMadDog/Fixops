/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AutoRemediationAction } from './AutoRemediationAction';
import type { IntelligenceLink } from './IntelligenceLink';
import type { SuiteStatus } from './SuiteStatus';
import type { ThreatPulse } from './ThreatPulse';
export type NerveCenterState = {
    threat_pulse: ThreatPulse;
    suites: Array<SuiteStatus>;
    intelligence_links: Array<IntelligenceLink>;
    recent_actions: Array<AutoRemediationAction>;
    pipeline_throughput: Record<string, any>;
    decision_engine: Record<string, any>;
    compliance_posture: Record<string, any>;
};

