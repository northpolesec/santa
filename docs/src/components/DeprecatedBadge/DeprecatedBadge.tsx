import { CircleMinus } from "lucide-react";

export default function DeprecatedBadge({
  deprecated,
}: {
  deprecated: string;
}) {
  return (
    <span className="badge badge--warning text-xs py-0.5 mx-2">
      <CircleMinus className="size-4 align-bottom" /> {deprecated}
    </span>
  );
}
