/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Payload for save-analysis.
 *
 * One of ``payload`` (JSON dict) or ``payload_base64`` (base64-encoded
 * UTF-8 JSON) must be supplied. ``payload_base64`` is provided so clients
 * that need to send multipart-adjacent content (raw scanner output) can
 * wrap it without escaping. The server always stores the decoded dict.
 */
export type SaveAnalysisRequest = {
    repo_path: string;
    payload?: (Record<string, any> | null);
    payload_base64?: (string | null);
};

