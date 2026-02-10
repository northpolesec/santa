import type { Monaco } from "@monaco-editor/react";
import { VARIABLES, FUNCTIONS, CONSTANT_NAMES } from "./constants";

export function registerCelLanguage(monaco: Monaco) {
  const alreadyRegistered = monaco.languages
    .getLanguages()
    .some((lang) => lang.id === "cel");
  if (alreadyRegistered) return;

  monaco.languages.register({ id: "cel" });
  monaco.languages.setMonarchTokensProvider("cel", {
    constants: CONSTANT_NAMES,
    functions: FUNCTIONS,
    variables: VARIABLES,
    keywords: ["true", "false", "null", "in"],
    tokenizer: {
      root: [
        [/"/, "string", "@string_double"],
        [/'/, "string", "@string_single"],
        [/\d+(\.\d+)?([eE][+-]?\d+)?/, "number"],
        [
          /[a-zA-Z_]\w*/,
          {
            cases: {
              "@constants": "constant",
              "@functions": "keyword.function",
              "@variables": "variable",
              "@keywords": "keyword",
              "@default": "identifier",
            },
          },
        ],
        [/[=><!~?:&|+\-*\/^%]+/, "operator"],
        [/[{}()\[\]]/, "delimiter.bracket"],
        [/[.,;]/, "delimiter"],
        [/\s+/, "white"],
      ],
      string_double: [
        [/[^\\"]+/, "string"],
        [/\\./, "string.escape"],
        [/"/, "string", "@pop"],
      ],
      string_single: [
        [/[^\\']+/, "string"],
        [/\\./, "string.escape"],
        [/'/, "string", "@pop"],
      ],
    },
  } as any);
}

export function registerCelCompletionProvider(monaco: Monaco) {
  const Snippet =
    monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet;

  return monaco.languages.registerCompletionItemProvider("cel", {
    triggerCharacters: ["."],
    provideCompletionItems: (model, position) => {
      const word = model.getWordUntilPosition(position);
      const range = {
        startLineNumber: position.lineNumber,
        endLineNumber: position.lineNumber,
        startColumn: word.startColumn,
        endColumn: word.endColumn,
      };

      const textUntilPosition = model.getValueInRange({
        startLineNumber: position.lineNumber,
        startColumn: 1,
        endLineNumber: position.lineNumber,
        endColumn: position.column,
      });

      // After a dot — suggest properties and methods
      if (/\w+\.\w*$/.test(textUntilPosition)) {
        const suggestions: any[] = [];

        if (/\btarget\.\w*$/.test(textUntilPosition)) {
          suggestions.push(
            {
              label: "signing_time",
              kind: monaco.languages.CompletionItemKind.Property,
              insertText: "signing_time",
              range,
            },
            {
              label: "secure_signing_time",
              kind: monaco.languages.CompletionItemKind.Property,
              insertText: "secure_signing_time",
              range,
            },
          );
        }

        // CEL string methods
        for (const [name, snippet] of [
          ["contains", "contains(${1})"],
          ["startsWith", "startsWith(${1})"],
          ["endsWith", "endsWith(${1})"],
          ["matches", "matches(${1})"],
          ["lowerAscii", "lowerAscii()"],
          ["upperAscii", "upperAscii()"],
          ["size", "size()"],
          ["join", "join(${1})"],
        ]) {
          suggestions.push({
            label: name,
            kind: monaco.languages.CompletionItemKind.Method,
            insertText: snippet,
            insertTextRules: Snippet,
            range,
          });
        }

        // CEL list macros
        for (const [name, snippet] of [
          ["exists", "exists(${1})"],
          ["all", "all(${1})"],
          ["filter", "filter(${1})"],
          ["map", "map(${1})"],
        ]) {
          suggestions.push({
            label: name,
            kind: monaco.languages.CompletionItemKind.Method,
            insertText: snippet,
            insertTextRules: Snippet,
            range,
          });
        }

        return { suggestions };
      }

      // Not after a dot — suggest constants, functions, variables, keywords
      const suggestions: any[] = [];

      for (const name of CONSTANT_NAMES) {
        suggestions.push({
          label: name,
          kind: monaco.languages.CompletionItemKind.Constant,
          insertText: name,
          range,
        });
      }

      suggestions.push(
        {
          label: "timestamp",
          kind: monaco.languages.CompletionItemKind.Function,
          insertText: "timestamp('${1}')",
          insertTextRules: Snippet,
          range,
        },
        {
          label: "require_touchid_with_cooldown_minutes",
          kind: monaco.languages.CompletionItemKind.Function,
          insertText: "require_touchid_with_cooldown_minutes(${1:minutes})",
          insertTextRules: Snippet,
          range,
        },
        {
          label: "require_touchid_only_with_cooldown_minutes",
          kind: monaco.languages.CompletionItemKind.Function,
          insertText:
            "require_touchid_only_with_cooldown_minutes(${1:minutes})",
          insertTextRules: Snippet,
          range,
        },
      );

      for (const name of VARIABLES) {
        suggestions.push({
          label: name,
          kind: monaco.languages.CompletionItemKind.Variable,
          insertText: name,
          range,
        });
      }

      for (const name of ["true", "false", "null", "in"]) {
        suggestions.push({
          label: name,
          kind: monaco.languages.CompletionItemKind.Keyword,
          insertText: name,
          range,
        });
      }

      return { suggestions };
    },
  });
}
