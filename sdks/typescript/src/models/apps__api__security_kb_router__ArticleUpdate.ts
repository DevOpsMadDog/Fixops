/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ArticleCategory } from './ArticleCategory';
export type apps__api__security_kb_router__ArticleUpdate = {
    title?: (string | null);
    content?: (string | null);
    category?: (ArticleCategory | null);
    tags?: (Array<string> | null);
    cwe_ids?: (Array<string> | null);
    owasp_ids?: (Array<string> | null);
    language?: (string | null);
    framework?: (string | null);
    severity_context?: (string | null);
    author?: (string | null);
};

