// A code block offers its contents as a file download by naming its fence
// title="something.mobileconfig". The title bar then hosts all of the block's
// controls, so both the Title and Buttons swizzles gate on this.
const DOWNLOADABLE = ".mobileconfig";

export function downloadableFilename(title: unknown): string | undefined {
  return typeof title === "string" && title.endsWith(DOWNLOADABLE)
    ? title
    : undefined;
}
