import type { ReactNode } from "react";
import { CircleMinus } from "lucide-react";

import { default as DeprecatedBadgeBase } from "@site/src/components/DeprecatedBadge/DeprecatedBadge";

export interface versioned {
  versionAdded?: string;
  versionDeprecated?: string;
}

export default function DeprecatedBadge({ k }: { k: versioned }): ReactNode {
  return k.versionDeprecated ? (
    <DeprecatedBadgeBase deprecated={k.versionDeprecated} />
  ) : (
    <></>
  );
}
