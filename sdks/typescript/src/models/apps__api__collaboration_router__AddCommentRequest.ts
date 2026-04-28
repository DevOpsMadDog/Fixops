/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to add a comment.
 */
export type apps__api__collaboration_router__AddCommentRequest = {
    entity_type: string;
    entity_id: string;
    org_id: string;
    author: string;
    content: string;
    author_email?: (string | null);
    is_internal?: boolean;
    parent_comment_id?: (string | null);
    metadata?: (Record<string, any> | null);
};

