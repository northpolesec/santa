import type { ReactNode } from "react";

import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";

import Heading from "@theme/Heading";

import { Badge } from "@site/src/components/shadcn/badge";
import { Separator } from "@site/src/components/shadcn/separator";

import { SantaConfigKey, SantaPossibleValue } from "@site/src/lib/santaconfig";

import TypeBadge from "./TypeBadge";
import AddedBadge from "./AddedBadge";
import DeprecatedBadge from "./DeprecatedBadge";
import RemovedBadge from "./RemovedBadge";

function AllowedValues({
  values,
}: {
  values: SantaPossibleValue[];
}): ReactNode {
  return (
    <>
      <strong>Allowed values:</strong>
      <ul>
        {values.map((value) => (
          <li key={value.value}>
            <code>{value.value}</code>
            {value.label && <span> ({value.label})</span>}

            {value.description && `: ${value.description}`}

            <DeprecatedBadge k={value} />
            <AddedBadge k={value} />
            <RemovedBadge k={value} />
          </li>
        ))}
      </ul>
    </>
  );
}

function ConfigKey({ k }: { k: SantaConfigKey }): ReactNode {
  return (
    <>
      <section>
        <header className="my-4">
          <Heading as="h3" id={`${k.key}`} className="my-2">
            {k.key}
            <span>
              <TypeBadge k={k} />
              <DeprecatedBadge k={k} />
              <AddedBadge k={k} />
              <RemovedBadge k={k} />
            </span>
          </Heading>
        </header>

        <span className="text-small">
          <div>
            {k.defaultValue !== undefined && (
              <>
                <strong>Default:</strong>
                <Badge className="mx-2" variant="outline">
                  {k.defaultValue.toString()}
                </Badge>
              </>
            )}
          </div>
          <div>
            {k.possibleValues && <AllowedValues values={k.possibleValues} />}
          </div>
        </span>

        <div>
          <Markdown remarkPlugins={[remarkGfm]}>{k.description}</Markdown>
        </div>
      </section>
    </>
  );
}

export default function ConfigKeyList({
  list,
}: {
  list: SantaConfigKey[];
}): ReactNode {
  return (
    <>
      <div className="px-6">
        {list.map((key) => (
          <div key={key.key} className="py-4">
            <ConfigKey k={key} />
          </div>
        ))}
      </div>
      <Separator />
    </>
  );
}
