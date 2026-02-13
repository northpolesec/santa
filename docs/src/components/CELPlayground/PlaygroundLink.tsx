import { encodePlaygroundState } from "./encoding";

function dedent(s: string): string {
  const lines = s.split("\n");
  // Remove leading/trailing empty lines
  while (lines.length && lines[0].trim() === "") lines.shift();
  while (lines.length && lines[lines.length - 1].trim() === "") lines.pop();
  // Find minimum indentation across non-empty lines
  const indent = Math.min(
    ...lines.filter((l) => l.trim()).map((l) => l.match(/^ */)![0].length),
  );
  return lines.map((l) => l.slice(indent)).join("\n");
}

export default function PlaygroundLink({
  expression,
  context,
}: {
  expression: string;
  context: string;
}) {
  const hash = encodePlaygroundState(dedent(expression), dedent(context));
  return (
    <div className="flex justify-end">
      <a
        href={`/cookbook/cel-playground#${hash}`}
        className="inline-block px-2 py-0.5 rounded border border-border text-xs font-medium no-underline hover:bg-secondary transition-colors"
      >
        Try in Playground →
      </a>
    </div>
  );
}
