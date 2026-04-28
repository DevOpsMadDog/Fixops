/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CopilotAgentType } from './CopilotAgentType';
/**
 * Chat session response.
 */
export type api__copilot_router__SessionResponse = {
    id: string;
    name: string;
    agent_type: CopilotAgentType;
    created_at: string;
    updated_at: string;
    message_count?: number;
    context?: Record<string, any>;
};

