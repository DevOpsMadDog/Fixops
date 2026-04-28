/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CopilotAgentType } from './CopilotAgentType';
/**
 * Request to send a message in a session.
 */
export type SendMessageRequest = {
    message: string;
    /**
     * Override agent for this message
     */
    agent_type?: (CopilotAgentType | null);
    /**
     * Include session context
     */
    include_context?: boolean;
};

