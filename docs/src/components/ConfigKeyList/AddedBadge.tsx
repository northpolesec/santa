import type { ReactNode } from "react";

import { default as AddedBadgeBase } from "@site/src/components/AddedBadge/AddedBadge";

export interface versioned {
  versionAdded?: string;
  versionDeprecated?: string;
  versionRemoved?: string;
}

export default function AddedBadge({ k }: { k: versioned }): ReactNode {
  if (k.versionDeprecated || k.versionRemoved) {
    return <></>;
  }
  return k.versionAdded ? <AddedBadgeBase added={k.versionAdded} /> : <></>;
}
