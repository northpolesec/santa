import { CircleX } from "lucide-react";

export default function RemovedBadge({ removed }: { removed: string }) {
  return (
    <span className="badge text-xs py-0.5 mx-2 bg-gray-700 text-white">
      <CircleX className="size-4 align-bottom" /> {removed}
    </span>
  );
}
