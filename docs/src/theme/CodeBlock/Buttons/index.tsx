import React from "react";
import Buttons from "@theme-original/CodeBlock/Buttons";
import type ButtonsType from "@theme/CodeBlock/Buttons";
import type { WrapperProps } from "@docusaurus/types";
import { useCodeBlockContext } from "@docusaurus/theme-common/internal";
import { downloadableFilename } from "../downloadable";

type Props = WrapperProps<typeof ButtonsType>;

// Downloadable blocks show these buttons in the title bar instead, next to the
// download control, so the group floating over the code would be a duplicate.
export default function ButtonsWrapper(props: Props): React.ReactNode {
  const { metadata } = useCodeBlockContext();
  return downloadableFilename(metadata.title) ? null : <Buttons {...props} />;
}
