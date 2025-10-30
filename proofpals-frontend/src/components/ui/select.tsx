import * as React from "react"

interface SelectContextValue {
  value?: string
  onValueChange?: (value: string) => void
  open: boolean
  setOpen: (open: boolean) => void
}

const SelectContext = React.createContext<SelectContextValue>({
  open: false,
  setOpen: () => {},
})

export interface SelectProps extends React.HTMLAttributes<HTMLDivElement> {
  value?: string
  onValueChange?: (value: string) => void
}

const Select = React.forwardRef<HTMLDivElement, SelectProps>(
  ({ children, value, onValueChange, className, ...props }, ref) => {
    const [open, setOpen] = React.useState(false)
    return (
      <SelectContext.Provider value={{ value, onValueChange, open, setOpen }}>
        <div
          ref={ref}
          className={className}
          {...props}
        >
          {children}
        </div>
      </SelectContext.Provider>
    )
  }
)
Select.displayName = "Select"

const SelectTrigger = React.forwardRef<HTMLButtonElement, React.ButtonHTMLAttributes<HTMLButtonElement>>(
  ({ children, className, ...props }, ref) => {
    const { open, setOpen } = React.useContext(SelectContext)
    return (
      <button
        ref={ref}
        type="button"
        className={className ?? "flex w-full items-center justify-between rounded-md border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500"}
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
        {...props}
      >
        {children}
        <svg className="ml-2 h-4 w-4 text-gray-500" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
          <path fillRule="evenodd" d="M5.23 7.21a.75.75 0 011.06.02L10 10.94l3.71-3.71a.75.75 0 111.06 1.06l-4.24 4.24a.75.75 0 01-1.06 0L5.21 8.29a.75.75 0 01.02-1.08z" clipRule="evenodd" />
        </svg>
      </button>
    )
  }
)
SelectTrigger.displayName = "SelectTrigger"

const SelectValue = React.forwardRef<HTMLSpanElement, { placeholder?: string } & React.HTMLAttributes<HTMLSpanElement>>(
  ({ placeholder, className, ...props }, ref) => {
    const { value } = React.useContext(SelectContext)
    return (
      <span
        ref={ref}
        className={className ?? "text-left"}
        {...props}
      >
        {value ?? placeholder}
      </span>
    )
  }
)
SelectValue.displayName = "SelectValue"

const SelectContent = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ children, className, ...props }, ref) => {
    const { open } = React.useContext(SelectContext)
    if (!open) return null
    return (
      <div
        ref={ref}
        className={className ?? "mt-1 w-full rounded-md border border-gray-300 bg-white shadow-lg"}
        role="listbox"
        {...props}
      >
        <ul className="max-h-60 overflow-auto py-1">
          {children}
        </ul>
      </div>
    )
  }
)
SelectContent.displayName = "SelectContent"

interface SelectItemProps extends React.LiHTMLAttributes<HTMLLIElement> {
  value: string
}

const SelectItem = React.forwardRef<HTMLLIElement, SelectItemProps>(
  ({ children, value, className, ...props }, ref) => {
    const context = React.useContext(SelectContext)

    const handleClick = () => {
      context.onValueChange?.(value)
      context.setOpen(false)
    }

    return (
      <li
        ref={ref}
        className={className ?? "cursor-pointer px-3 py-2 text-sm text-gray-900 hover:bg-gray-100"}
        onClick={handleClick}
        role="option"
        aria-selected={context.value === value}
        {...props}
      >
        {children}
      </li>
    )
  }
)
SelectItem.displayName = "SelectItem"

export { Select, SelectTrigger, SelectValue, SelectContent, SelectItem }

