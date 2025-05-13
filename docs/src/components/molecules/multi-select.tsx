import useIsBrowser from "@docusaurus/useIsBrowser";

import { X as RemoveIcon } from "lucide-react";
import Select, {
  components,
  MultiValueRemoveProps,
  Props as SelectProps,
} from "react-select";

import { cn } from "../shadcn/utils";

export interface Option {
  label: string;
  value: string;
}

interface MultiSelectorProps
  extends Omit<SelectProps<Option, true>, "value" | "onChange"> {
  values: string[];
  onValuesChange: (value: string[]) => void;
  className?: string;
}

const MultiValueRemove = (props: MultiValueRemoveProps<Option>) => {
  return (
    <components.MultiValueRemove {...props}>
      <RemoveIcon className="h-3 w-3" />
    </components.MultiValueRemove>
  );
};

export function MultiSelector({
  values,
  onValuesChange,
  className,
  options,
  ...props
}: MultiSelectorProps) {
  const selectedOptions = values.map((value) => ({
    value,
    label: value,
  }));

  const isBrowser = useIsBrowser();

  return (
    <Select
      isMulti
      value={selectedOptions}
      onChange={(newValue) => {
        onValuesChange(newValue.map((v) => v.value));
      }}
      options={options}
      className={cn("w-full", className)}
      classNamePrefix="react-select"
      classNames={{
        control: () =>
          "!bg-transparent !border !border-input !shadow-none !py-1",
        placeholder: () => "!text-muted-foreground !text-sm",
        valueContainer: () => "!px-1.5 !gap-1",
        multiValue: () => "!bg-secondary !rounded-md !hover:bg-secondary/80",
        multiValueLabel: () => "!text-foreground !text-sm",
        multiValueRemove: () =>
          "!text-foreground !text-xs hover:!text-bright hover:!bg-muted",
        input: () => "!text-foreground !text-sm",
        menuPortal: () => "!z-[9999] pointer-events-auto",
        menu: () =>
          "!bg-transparent !shadow-none !border-none !overflow-hidden !rounded-md",
        menuList: () =>
          "!bg-background !border !border-input !shadow-none !rounded-md",
        option: ({ isFocused }) =>
          cn(
            "!text-foreground !text-sm !cursor-pointer",
            isFocused ? "!bg-muted" : "!bg-transparent"
          ),
      }}
      menuPortalTarget={isBrowser ? document.body : undefined}
      menuPosition="fixed"
      components={{
        MultiValueRemove,
      }}
      {...props}
    />
  );
}
