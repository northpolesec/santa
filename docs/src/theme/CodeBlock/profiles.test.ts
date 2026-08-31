import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "vitest";

// The CodeBlock wrapper only renders a download button for code blocks titled
// "*.mobileconfig", so a profile page that forgets the title silently loses it.
const dir = join(__dirname, "../../../docs/deployment");

for (const file of readdirSync(dir).filter((f) => f.startsWith("profile-"))) {
  test(`${file} example profile is downloadable`, () => {
    const fences = readFileSync(join(dir, file), "utf8")
      .split("\n")
      .filter((line) => line.startsWith("```xml"));
    expect(fences.length).toBe(1);
    expect(fences[0]).toMatch(/title="santa-[a-z-]+\.mobileconfig"/);
  });
}
