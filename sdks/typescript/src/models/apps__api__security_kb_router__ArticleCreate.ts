/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ArticleCategory } from './ArticleCategory';
export type apps__api__security_kb_router__ArticleCreate = {
    title: string;
    content: string;
    category: ArticleCategory;
    tags?: Array<string>;
    cwe_ids?: Array<string>;
    owasp_ids?: Array<string>;
    language?: (string | null);
    framework?: (string | null);
    severity_context?: (string | null);
    author?: string;
    org_id?: string;
};

