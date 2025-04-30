import type { ReactNode } from "react";
import { RefreshCcwIcon } from "lucide-react";

import { SantaConfigKey } from "@site/src/lib/santaconfig";

export default function TypeBadge({ k }: { k: SantaConfigKey }): ReactNode {
  return (
    <span className="badge badge--secondary mx-2 select-none docsearch-ignore">
      {k.repeated && "Array of "}
      {k.type}
      {k.repeated && "s"}
      {k.syncConfigurable && <RefreshCcwIcon className="ml-2 size-3" />}
    </span>
  );
}
