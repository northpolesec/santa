import React from "react";
import { useCodeBlockContext } from "@docusaurus/theme-common/internal";
import CopyButton from "@theme/CodeBlock/Buttons/CopyButton";
import WordWrapButton from "@theme/CodeBlock/Buttons/WordWrapButton";
import { Download } from "lucide-react";
import { downloadDataAsFile } from "@site/src/components/ConfigGenerator/plist";
import { downloadableFilename } from "../downloadable";
import styles from "./styles.module.css";

export default function CodeBlockTitle({
  children,
}: {
  children: React.ReactNode;
}): React.ReactNode {
  const { metadata } = useCodeBlockContext();
  const filename = downloadableFilename(children);

  if (!filename) {
    return children;
  }

  return (
    <span className={styles.titleRow}>
      <span className={styles.name}>{filename}</span>
      <span className={styles.actions}>
        <WordWrapButton className={styles.action} />
        <CopyButton className={styles.action} />
        <button
          type="button"
          className={styles.action}
          aria-label={`Download ${filename}`}
          onClick={() => downloadDataAsFile(filename, metadata.code)}
        >
          <Download aria-hidden="true" className={styles.downloadIcon} />
          Download
        </button>
      </span>
    </span>
  );
}
