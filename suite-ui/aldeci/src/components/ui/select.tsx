import * as React from 'react';
import { cn } from '../../lib/utils';
import { ChevronDown } from 'lucide-react';

// ── Native select wrapper with ALdeci styling ──────────────────────────────
// Uses native <select> for full accessibility and mobile support.
// Styled to match shadcn/ui dark theme.

export interface SelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> {
  placeholder?: string;
}

const Select = React.forwardRef<HTMLSelectElement, SelectProps>(
  ({ className, children, placeholder, ...props }, ref) => {
    return (
      <div className="relative">
        <select
          ref={ref}
          className={cn(
            'flex h-10 w-full items-center rounded-md border border-gray-700/50 bg-gray-900/50 px-3 py-2 text-sm text-slate-200',
            'ring-offset-background focus:outline-none focus:ring-2 focus:ring-indigo-500/40 focus:ring-offset-2 focus:ring-offset-gray-900',
            'disabled:cursor-not-allowed disabled:opacity-50',
            'appearance-none cursor-pointer',
            'transition-colors hover:border-gray-600/60',
            className
          )}
          {...props}
        >
          {placeholder && (
            <option value="" disabled>
              {placeholder}
            </option>
          )}
          {children}
        </select>
        <ChevronDown className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
      </div>
    );
  }
);
Select.displayName = 'Select';

// ── SelectOption for convenience ──────────────────────────────────────────

export interface SelectOptionProps extends React.OptionHTMLAttributes<HTMLOptionElement> {}

const SelectOption = React.forwardRef<HTMLOptionElement, SelectOptionProps>(
  ({ className, ...props }, ref) => {
    return (
      <option
        ref={ref}
        className={cn('bg-gray-900 text-slate-200', className)}
        {...props}
      />
    );
  }
);
SelectOption.displayName = 'SelectOption';

export { Select, SelectOption };
