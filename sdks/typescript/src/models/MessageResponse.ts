/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CopilotAgentType } from './CopilotAgentType';
import type { MessageRole } from './MessageRole';
/**
 * Message in conversation.
 */
export type MessageResponse = {
    id: string;
    session_id: string;
    role: MessageRole;
    content: string;
    agent_type?: (CopilotAgentType | null);
    timestamp: string;
    metadata?: Record<string, any>;
    actions?: Array<Record<string, any>>;
};

