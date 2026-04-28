/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CopilotAgentType } from './CopilotAgentType';
/**
 * Request to create a new chat session.
 */
export type api__copilot_router__CreateSessionRequest = {
    /**
     * Session name
     */
    name?: (string | null);
    /**
     * Primary agent for this session
     */
    agent_type?: CopilotAgentType;
    /**
     * Initial context (e.g., CVE IDs, asset IDs)
     */
    context?: (Record<string, any> | null);
};

