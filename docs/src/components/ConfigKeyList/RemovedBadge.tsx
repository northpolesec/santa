import type { ReactNode } from "react";

import { default as RemovedBadgeBase } from "@site/src/components/RemovedBadge/RemovedBadge";

export interface versioned {
  versionAdded?: string;
  versionDeprecated?: string;
  versionRemoved?: string;
}

export default function RemovedBadge({ k }: { k: versioned }): ReactNode {
  return k.versionRemoved ? (
    <RemovedBadgeBase removed={k.versionRemoved} />
  ) : (
    <></>
  );
}
