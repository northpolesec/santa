import { SantaConfigKey, SantaConfigAllKeys } from "@site/src/lib/santaconfig";

export function generatePlist(data: any) {
  return `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
  <dict>
${Object.entries(data)
  .map(([key, value]) => {
    if (value == undefined || value === "") return undefined;
    if (
      isDefault(
        SantaConfigAllKeys.find((k) => k.key === key),
        value
      )
    ) {
      return undefined;
    }

    const k = `    <key>${key}</key>\n`;
    switch (typeof value) {
      case "boolean":
        if (value) {
          return `${k}    <true/>`;
        } else {
          return `${k}    <false/>`;
        }
      case "string":
        return `${k}    <string>${value}</string>`;
      case "number":
        return `${k}    <integer>${value}</integer>`;
      case "object":
        return `${k}    <array>\n${value.map((v) => `      <string>${v}</string>`).join("\n")}\n    </array>`;
    }
  })
  .filter((v) => v !== undefined)
  .join("\n")}
  </dict>
</plist>
`;
}

// Triggers a download of the provided data passing the filename as a hint for
// browser to store it under.
export function downloadDataAsFile(filename: string, data: string) {
  var element = document.createElement("a");
  element.setAttribute(
    "href",
    "data:text/plain;charset=utf-8," + encodeURIComponent(data)
  );
  element.setAttribute("download", filename);
  element.style.display = "none";
  document.body.appendChild(element);

  element.click();

  document.body.removeChild(element);
}

// Returns true if the provided value is the default value for the given key.
// Handles special cases for some keys, handles undefined defaults and handles
// repeated fields.
function isDefault(key: SantaConfigKey, value: any) {
  if (key.key == "Telemetry") return false;

  if (key.defaultValue === undefined) return false;

  if (key.repeated) {
    return (
      key.defaultValue?.length === value.length &&
      key.defaultValue?.every((element, index) => element === value[index])
    );
  }
  return key.defaultValue === value;
}
