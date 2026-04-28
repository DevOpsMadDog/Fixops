/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response returned to Slack after a slash command.
 */
export type SlackCommandResponse = {
    /**
     * 'in_channel' or 'ephemeral'
     */
    response_type?: string;
    blocks?: Array<any>;
    text?: (string | null);
};

