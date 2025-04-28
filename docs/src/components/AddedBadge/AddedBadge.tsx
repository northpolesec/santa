import { CirclePlus } from "lucide-react";

export default function AddedBadge({ added }: { added: string }) {
  return (
    <span className="badge badge--info text-xs py-0.5 mx-2">
      <CirclePlus className="size-4 align-bottom" /> {added}
    </span>
  );
}
