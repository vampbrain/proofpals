// src/components/ui/alert-dialog.tsx
// Styled alert-dialog component set with Tailwind classes
import * as React from "react";
import { cn } from "@/lib/utils";

export interface AlertDialogProps {
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  children?: React.ReactNode;
}

export const AlertDialog: React.FC<AlertDialogProps> = ({ open = false, children }) => {
  if (!open) return null;
  return <div role="dialog" aria-modal="true">{children}</div>;
};

export const AlertDialogTrigger: React.FC<React.ButtonHTMLAttributes<HTMLButtonElement>> = ({ 
  className, 
  children, 
  ...props 
}) => {
  return (
    <button 
      className={cn("inline-flex items-center justify-center rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:opacity-50 disabled:pointer-events-none", className)} 
      {...props}
    >
      {children}
    </button>
  );
};

export const AlertDialogContent: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({ 
  className, 
  children, 
  ...props 
}) => {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div 
        role="dialog" 
        className={cn("relative bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6 max-w-md w-full mx-auto", className)} 
        {...props}
      >
        {children}
      </div>
    </div>
  );
};

export const AlertDialogHeader: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({ 
  className, 
  children, 
  ...props 
}) => {
  return <div className={cn("mb-4 space-y-2", className)} {...props}>{children}</div>;
};

export const AlertDialogTitle: React.FC<React.HTMLAttributes<HTMLHeadingElement>> = ({ 
  className, 
  children, 
  ...props 
}) => {
  return <h2 className={cn("text-lg font-semibold", className)} {...props}>{children}</h2>;
};

export const AlertDialogDescription: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({ 
  className, 
  children, 
  ...props 
}) => {
  return <div className={cn("text-sm text-gray-500 dark:text-gray-400", className)} {...props}>{children}</div>;
};

export const AlertDialogFooter: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({ 
  className, 
  children, 
  ...props 
}) => {
  return <div className={cn("mt-6 flex justify-end space-x-2", className)} {...props}>{children}</div>;
};

export const AlertDialogCancel: React.FC<React.ButtonHTMLAttributes<HTMLButtonElement>> = ({ 
  className, 
  children, 
  ...props 
}) => {
  return (
    <button 
      type="button" 
      className={cn("px-4 py-2 rounded-md border border-gray-300 text-sm font-medium text-gray-700 hover:bg-gray-50 dark:border-gray-600 dark:text-gray-300 dark:hover:bg-gray-700", className)} 
      {...props}
    >
      {children}
    </button>
  );
};

export const AlertDialogAction: React.FC<React.ButtonHTMLAttributes<HTMLButtonElement>> = ({ 
  className, 
  children, 
  ...props 
}) => {
  return (
    <button 
      className={cn("px-4 py-2 rounded-md bg-blue-600 text-white text-sm font-medium hover:bg-blue-700 dark:bg-blue-700 dark:hover:bg-blue-800", className)} 
      {...props}
    >
      {children}
    </button>
  );
};