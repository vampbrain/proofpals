import * as React from "react";
import { cn } from "@/lib/utils/formatting";

interface ProgressProps extends React.HTMLAttributes<HTMLDivElement> {
  value?: number;
  max?: number;
  indicatorClassName?: string;
}

const Progress = React.forwardRef<HTMLDivElement, ProgressProps>(
  ({ className, value = 0, max = 100, indicatorClassName, ...props }, ref) => {
    const clampedMax = Math.max(max, 1);
    const clampedValue = Math.min(Math.max(value, 0), clampedMax);
    const percentage = (clampedValue / clampedMax) * 100;

    return (
      <div
        ref={ref}
        className={cn("relative h-2 w-full overflow-hidden rounded", className)}
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={clampedMax}
        aria-valuenow={clampedValue}
        {...props}
      >
        <div
          className={cn("h-full bg-primary", indicatorClassName)}
          style={{ width: `${percentage}%` }}
        />
      </div>
    );
  }
);

Progress.displayName = "Progress";

export { Progress };