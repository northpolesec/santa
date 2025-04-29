import { useEffect } from "react";
import { useHistory } from "@docusaurus/router";

export default function HomepageFeatures() {
  const history = useHistory();

  useEffect(() => {
    history.replace("/intro");
  }, [history]);

  return null;
}
