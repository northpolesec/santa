import { useState, useEffect, useRef } from "react";
import Editor, { type Monaco } from "@monaco-editor/react";
import type { editor } from "monaco-editor";
import { useColorMode } from "@docusaurus/theme-common";
import { registerCELLanguage } from "./autocompletion";
import { VARIABLES } from "./constants";
import { convertEsloggerEvent } from "./eslogger";
import {
  evaluate,
  DEFAULT_EXPRESSION,
  DEFAULT_YAML,
  type EvalResult,
} from "./eval";

const commonEditorOptions = {
  minimap: { enabled: false },
  wordWrap: "on" as const,
  scrollBeyondLastLine: false,
  automaticLayout: true,
  padding: { top: 8, bottom: 8 },
};

const celEditorOptions = {
  ...commonEditorOptions,
  lineNumbers: "on" as const,
  lineNumbersMinChars: 3,
  folding: false,
  glyphMargin: false,
  wordBasedSuggestions: "off" as const,
};

const dataEditorOptions = {
  ...commonEditorOptions,
  lineNumbers: "on" as const,
  lineNumbersMinChars: 3,
  tabSize: 2,
};

function encodePlaygroundState(expr: string, yaml: string): string {
  return btoa(JSON.stringify({ e: expr, c: yaml }));
}

function decodePlaygroundState(
  hash: string,
): { expression: string; context: string } | null {
  try {
    const data = JSON.parse(atob(hash));
    if (typeof data.e === "string" && typeof data.c === "string") {
      return { expression: data.e, context: data.c };
    }
  } catch {
    // ignore malformed hash
  }
  return null;
}

export default function CELPlayground() {
  const { colorMode } = useColorMode();
  const [expression, setExpression] = useState(DEFAULT_EXPRESSION);
  const [yamlInput, setYamlInput] = useState(DEFAULT_YAML);
  const [result, setResult] = useState<EvalResult | null>(null);
  const [showImport, setShowImport] = useState(false);
  const [esloggerJson, setEsloggerJson] = useState("");
  const [importError, setImportError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const completionDisposableRef = useRef<{ dispose(): void } | null>(null);

  useEffect(() => {
    const hash = window.location.hash.slice(1);
    if (hash) {
      const state = decodePlaygroundState(hash);
      if (state) {
        setExpression(state.expression);
        setYamlInput(state.context);
      }
    }
    return () => {
      completionDisposableRef.current?.dispose();
    };
  }, []);

  const editorTheme = colorMode === "dark" ? "vs-dark" : "light";

  function handleImport() {
    try {
      const yaml = convertEsloggerEvent(esloggerJson);
      setYamlInput(yaml);
      setEsloggerJson("");
      setShowImport(false);
      setImportError(null);
    } catch (err) {
      setImportError(err instanceof Error ? err.message : String(err));
    }
  }

  function handleEvaluate() {
    setResult(evaluate(expression, yamlInput));
  }

  function handleCopyLink() {
    const hash = encodePlaygroundState(expression, yamlInput);
    const url = `${window.location.origin}${window.location.pathname}#${hash}`;
    navigator.clipboard.writeText(url).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  return (
    <div className="flex flex-col gap-4 mb-4">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="flex flex-col gap-2">
          <div className="flex items-center min-h-8">
            <label className="text-sm font-medium text-foreground">
              CEL Expression
            </label>
          </div>
          {/* Stop key events from reaching Docusaurus search shortcut handler */}
          <div className="rounded-md border border-border overflow-hidden" onKeyDown={(e) => e.stopPropagation()}>
            <Editor
              height="280px"
              language="cel"
              theme={editorTheme}
              value={expression}
              onChange={(value) => setExpression(value ?? "")}
              beforeMount={(monaco) =>
                registerCELLanguage(monaco, { variables: VARIABLES })
              }
              options={celEditorOptions}
            />
          </div>
        </div>
        <div className="flex flex-col gap-2">
          <div className="flex items-center justify-between min-h-8">
            <label
              htmlFor={showImport ? "eslogger-json-input" : undefined}
              className="text-sm font-medium text-foreground"
            >
              {showImport
                ? "Input Context (eslogger JSON)"
                : "Input Context (YAML)"}
            </label>
            {showImport ? (
              <div className="flex items-center gap-2">
                <button
                  onClick={handleImport}
                  className="px-3 py-1 rounded-md bg-primary text-primary-foreground font-medium text-xs hover:bg-primary-hover transition-colors cursor-pointer"
                >
                  Import
                </button>
                <button
                  onClick={() => {
                    setShowImport(false);
                    setImportError(null);
                  }}
                  className="px-3 py-1 rounded-md bg-secondary text-secondary-foreground font-medium text-xs hover:bg-[hsl(var(--secondary-hover))] transition-colors cursor-pointer"
                >
                  Cancel
                </button>
              </div>
            ) : (
              <button
                onClick={() => {
                  setShowImport(true);
                  setImportError(null);
                }}
                className="px-3 py-1 rounded-md bg-secondary text-secondary-foreground font-medium text-xs hover:bg-[hsl(var(--secondary-hover))] transition-colors cursor-pointer"
              >
                Import from eslogger
              </button>
            )}
          </div>
          {showImport ? (
            <>
              <textarea
                id="eslogger-json-input"
                value={esloggerJson}
                onChange={(e) => {
                  setEsloggerJson(e.target.value);
                  setImportError(null);
                }}
                placeholder={
                  'Paste output from "eslogger exec" here. Only the first event will be used.\n\nNote: eslogger events don\'t include signing times, so fake timestamps will be added.'
                }
                className="w-full min-h-[280px] p-3 rounded-md border border-border bg-card text-card-foreground font-mono text-sm resize-y focus:outline-none focus:ring-2 focus:ring-ring"
                spellCheck={false}
              />
              {importError && (
                <p className="text-xs text-[hsl(var(--destructive))] m-0">
                  {importError}
                </p>
              )}
            </>
          ) : (
            <div className="rounded-md border border-border overflow-hidden" onKeyDown={(e) => e.stopPropagation()}>
              <Editor
                height="280px"
                language="yaml"
                theme={editorTheme}
                value={yamlInput}
                onChange={(value) => setYamlInput(value ?? "")}
                options={dataEditorOptions}
              />
            </div>
          )}
        </div>
      </div>

      <div className="flex items-center gap-2">
        <button
          onClick={handleEvaluate}
          className="px-4 py-2 rounded-md bg-primary text-primary-foreground font-medium text-sm hover:bg-primary-hover transition-colors cursor-pointer"
        >
          Evaluate
        </button>
        <button
          onClick={handleCopyLink}
          className="px-4 py-2 rounded-md bg-secondary text-secondary-foreground font-medium text-sm hover:bg-[hsl(var(--secondary-hover))] transition-colors cursor-pointer"
        >
          {copied ? "Copied!" : "Copy Link"}
        </button>
      </div>

      {result && (
        <div className="rounded-md border border-border bg-card p-4">
          {result.valid ? (
            <div className="flex flex-col gap-2">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-foreground">
                  Result:
                </span>
                <code className="px-2 py-0.5 rounded bg-accent text-accent-foreground text-sm font-mono">
                  {result.value}
                </code>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-foreground">
                  Cacheable:
                </span>
                <span
                  className={`text-sm ${result.cacheable ? "text-[hsl(var(--success))]" : "text-[hsl(var(--destructive))]"}`}
                >
                  {result.cacheable ? "Yes" : "No"}
                </span>
                <span className="text-xs text-muted-foreground">
                  {result.cacheable
                    ? "(expression only uses static target fields)"
                    : "(expression references dynamic fields: args, envs, euid, or cwd)"}
                </span>
              </div>
              {result.isV2 && (
                <div className="mt-1 rounded-md border border-border bg-accent p-3 text-sm text-accent-foreground">
                  This expression uses CELv2 features which are only available
                  to Workshop customers.
                </div>
              )}
            </div>
          ) : (
            <div className="rounded-md bg-[hsl(var(--destructive)/0.1)] border border-[hsl(var(--destructive)/0.3)] p-3">
              <pre className="text-sm text-[hsl(var(--destructive))] font-mono whitespace-pre-wrap m-0">
                {result.error}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
