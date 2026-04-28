/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { WidgetType } from './WidgetType';
/**
 * A single visual unit rendered on a dashboard.
 */
export type DashboardWidget = {
    id?: string;
    title: string;
    type: WidgetType;
    data?: Record<string, any>;
    config?: Record<string, any>;
};

