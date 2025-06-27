import type { ReactNode } from "react";

import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";

import { downloadDataAsFile, generatePlist } from "./plist";

import { zodResolver } from "@hookform/resolvers/zod";
import { useForm, useFormContext } from "react-hook-form";
import { z } from "zod";

import { Switch } from "@site/src/components/shadcn/switch";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@site/src/components/shadcn/form";
import { MultiSelector } from "@site/src/components/molecules/multi-select";
import { Input } from "@site/src/components/shadcn/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@site/src/components/shadcn/select";
import { Button } from "@site/src/components/shadcn/button";

import { SantaConfigKey, SantaConfigAllKeys } from "@site/src/lib/santaconfig";

interface FieldRenderProps {
  value: any;
  onChange: (...event: any[]) => void;
}

function ConfigKeyBoolean({
  configKey,
  field,
}: {
  configKey: SantaConfigKey;
  field: FieldRenderProps;
}): ReactNode {
  return (
    <FormControl>
      <Switch
        {...field}
        checked={field.value}
        onCheckedChange={field.onChange}
      />
    </FormControl>
  );
}

function ConfigKeyString({
  configKey,
  field,
}: {
  configKey: SantaConfigKey;
  field: FieldRenderProps;
}): ReactNode {
  return (
    <FormControl>
      <Input
        {...field}
        className="pl-4"
        value={field.value}
        onChange={field.onChange}
        type={configKey.type === "integer" ? "number" : "text"}
      />
    </FormControl>
  );
}

function ConfigKeyList({
  configKey,
  field,
}: {
  configKey: SantaConfigKey;
  field: FieldRenderProps;
}): ReactNode {
  if (configKey.repeated) {
    // If possible values are defined, use MultiSelector
    if (configKey.possibleValues && configKey.possibleValues.length > 0) {
      return (
        <MultiSelector
          values={field.value || []}
          onValuesChange={field.onChange}
          options={configKey.possibleValues.map((value) => ({
            value: value.value,
            label: value.label ?? value.value,
          }))}
        />
      );
    }

    // For custom values with no pre-defined options
    return (
      <div className="space-y-2">
        {(field.value || []).map((value: string, index: number) => (
          <div key={index} className="flex items-center gap-2">
            <Input
              value={value}
              onChange={(e) => {
                const newValues = [...(field.value || [])];
                newValues[index] = e.target.value;
                field.onChange(newValues);
              }}
              className="pl-4 flex-1"
            />
            <Button
              type="button"
              onClick={() => {
                const newValues = [...(field.value || [])];
                newValues.splice(index, 1);
                field.onChange(newValues);
              }}
              className="p-2"
              aria-label="Remove item"
            >
              ✕
            </Button>
          </div>
        ))}
        <Button
          type="button"
          onClick={() => {
            field.onChange([...(field.value || []), ""]);
          }}
          className="p-2"
        >
          Add Item
        </Button>
      </div>
    );
  }

  return (
    <Select
      {...field}
      defaultValue={field.value}
      onValueChange={field.onChange}
    >
      <FormControl>
        <SelectTrigger>
          <SelectValue />
        </SelectTrigger>
      </FormControl>
      <SelectContent>
        {configKey.possibleValues.map((value) => (
          <SelectItem key={value.value} value={value.value.toString()}>
            {value.label ?? value.value}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

function ConfigKey({
  configKey,
  parent,
}: {
  configKey: SantaConfigKey;
  parent?: SantaConfigKey;
}): ReactNode {
  const { control, getValues } = useFormContext();

  const key = ((parent?.key && parent.key + ".") || "") + configKey.key;

  if (
    configKey.type === "dict" &&
    configKey.subFields?.length > 0 &&
    (configKey.enableIf?.(getValues()) ?? true)
  ) {
    return <ConfigDict configKeys={configKey.subFields} parent={parent} />;
  }

  return (
    <FormField
      control={control}
      name={key}
      disabled={!(configKey.enableIf?.(getValues()) ?? true)}
      render={({ field }) => (
        <FormItem className="mt-4">
          <FormLabel>{configKey.key}</FormLabel>
          <div className="text-[0.8rem] text-muted-foreground">
            <Markdown remarkPlugins={[remarkGfm]}>
              {configKey.description}
            </Markdown>
            <FormMessage />
          </div>

          {configKey.repeated && (configKey.enableIf?.(getValues()) ?? true) ? (
            <ConfigKeyList configKey={configKey} field={field} />
          ) : configKey.type === "string" || configKey.type === "integer" ? (
            <ConfigKeyString configKey={configKey} field={field} />
          ) : configKey.type === "bool" ? (
            <ConfigKeyBoolean configKey={configKey} field={field} />
          ) : (
            <p>This key is not yet supported by the generator</p>
          )}
        </FormItem>
      )}
    />
  );
}

function ConfigDict({
  configKeys,
  parent,
}: {
  configKeys: SantaConfigKey[];
  parent?: SantaConfigKey;
}): ReactNode {
  return (
    <>
      {configKeys
        .filter((key) => key.versionDeprecated == undefined) // filter out deprecated keys.
        .map((key) => (
          <ConfigKey key={key.key} parent={parent} configKey={key} />
        ))}
    </>
  );
}

export function ConfigGeneratorSection({
  list,
}: {
  list: SantaConfigKey[];
}): ReactNode {
  return (
    <section className="my-4">
      <div>
        <div>
          <ConfigDict configKeys={list} />
        </div>
      </div>
    </section>
  );
}

export function ConfigGeneratorForm({ children }: { children: ReactNode }) {
  function onSubmit(data: any) {
    downloadDataAsFile("santa.mobileconfig", generatePlist(data));
  }

  const formSchema = zodFormSchema();
  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: Object.fromEntries(
      SantaConfigAllKeys.filter(
        (key) => key.versionDeprecated == undefined
      ).map((key) => [key.key, key.defaultValue])
    ),
  });

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)}>{children}</form>
    </Form>
  );
}

function zodFormSchema() {
  return z.object(
    Object.fromEntries(
      SantaConfigAllKeys.filter(
        (key) => key.versionDeprecated == undefined
      ).map((key) => [key.key, zodTypeFromSantaConfigKey(key)])
    )
  );
}

function zodTypeFromSantaConfigKey(key: SantaConfigKey) {
  const inner = () => {
    switch (key.type) {
      case "string":
        return z.string();
      case "bool":
        return z.boolean();
      case "integer":
        return z.coerce.number();
      default:
        return z.any();
    }
  };

  if (key.repeated) {
    const t = z.array(inner()).optional().default(key.defaultValue);
    return t;
  }

  return inner().optional();
}
