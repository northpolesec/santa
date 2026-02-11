// CEL (Common Expression Language) language definition for Monaco Editor
// This module provides CEL syntax highlighting for @monaco-editor/react
// Reference: https://github.com/google/cel-spec/blob/master/doc/langdef.md

// Autocomplete items with documentation and snippets
export interface CELCompletionItem {
  label: string;
  kind: "keyword" | "function" | "snippet" | "type" | "macro";
  detail?: string;
  documentation?: string;
  insertText?: string;
  insertTextRules?: "insertAsSnippet";
}

// CEL Macros - expanded at parse time into comprehensions
export const celMacros: CELCompletionItem[] = [
  {
    label: "has",
    kind: "macro",
    detail: "has(field) -> bool",
    documentation:
      "Tests whether a field is available. For proto messages, tests whether a field is set. For maps, tests whether a key is present.",
    insertText: "has(${1:field})",
    insertTextRules: "insertAsSnippet",
  },
  {
    label: "all",
    kind: "macro",
    detail: "list.all(var, condition) -> bool",
    documentation:
      "Tests whether all elements in a list satisfy the given condition. Returns true for empty lists.",
    insertText: "${1:list}.all(${2:x}, ${3:condition})",
    insertTextRules: "insertAsSnippet",
  },
  {
    label: "exists",
    kind: "macro",
    detail: "list.exists(var, condition) -> bool",
    documentation:
      "Tests whether at least one element in a list satisfies the given condition. Returns false for empty lists.",
    insertText: "${1:list}.exists(${2:x}, ${3:condition})",
    insertTextRules: "insertAsSnippet",
  },
  {
    label: "exists_one",
    kind: "macro",
    detail: "list.exists_one(var, condition) -> bool",
    documentation:
      "Tests whether exactly one element in a list satisfies the given condition.",
    insertText: "${1:list}.exists_one(${2:x}, ${3:condition})",
    insertTextRules: "insertAsSnippet",
  },
  {
    label: "map",
    kind: "macro",
    detail: "list.map(var, expr) -> list",
    documentation:
      "Transforms each element in a list using the given expression. Returns a new list with transformed elements.",
    insertText: "${1:list}.map(${2:x}, ${3:expr})",
    insertTextRules: "insertAsSnippet",
  },
  {
    label: "filter",
    kind: "macro",
    detail: "list.filter(var, condition) -> list",
    documentation:
      "Returns a new list containing only elements that satisfy the given condition.",
    insertText: "${1:list}.filter(${2:x}, ${3:condition})",
    insertTextRules: "insertAsSnippet",
  },
];

// String functions
export const celStringFunctions: CELCompletionItem[] = [
  {
    label: "size",
    kind: "function",
    detail: "string.size() -> int",
    documentation:
      "Returns the number of code points in the string. Also works on bytes, lists, and maps.",
  },
  {
    label: "contains",
    kind: "function",
    detail: "string.contains(substring) -> bool",
    documentation: "Tests whether the string contains the given substring.",
  },
  {
    label: "startsWith",
    kind: "function",
    detail: "string.startsWith(prefix) -> bool",
    documentation: "Tests whether the string starts with the given prefix.",
  },
  {
    label: "endsWith",
    kind: "function",
    detail: "string.endsWith(suffix) -> bool",
    documentation: "Tests whether the string ends with the given suffix.",
  },
  {
    label: "matches",
    kind: "function",
    detail: "string.matches(regex) -> bool",
    documentation:
      "Tests whether the string matches the given RE2 regular expression.",
  },
  {
    label: "charAt",
    kind: "function",
    detail: "string.charAt(index) -> string",
    documentation: "Returns the character at the given index as a string.",
  },
  {
    label: "indexOf",
    kind: "function",
    detail: "string.indexOf(substring, [start]) -> int",
    documentation:
      "Returns the index of the first occurrence of the substring, or -1 if not found.",
  },
  {
    label: "lastIndexOf",
    kind: "function",
    detail: "string.lastIndexOf(substring, [start]) -> int",
    documentation:
      "Returns the index of the last occurrence of the substring, or -1 if not found.",
  },
  {
    label: "join",
    kind: "function",
    detail: "list.join([separator]) -> string",
    documentation:
      "Joins a list of strings with the given separator (default empty string).",
  },
  {
    label: "split",
    kind: "function",
    detail: "string.split(separator, [limit]) -> list(string)",
    documentation:
      "Splits the string by the separator. Optional limit restricts the number of splits.",
  },
  {
    label: "substring",
    kind: "function",
    detail: "string.substring(start, [end]) -> string",
    documentation:
      "Returns a substring from start index to end index (exclusive).",
  },
  {
    label: "trim",
    kind: "function",
    detail: "string.trim() -> string",
    documentation:
      "Returns the string with leading and trailing whitespace removed.",
  },
  {
    label: "lowerAscii",
    kind: "function",
    detail: "string.lowerAscii() -> string",
    documentation:
      "Returns the string with ASCII characters converted to lowercase.",
  },
  {
    label: "upperAscii",
    kind: "function",
    detail: "string.upperAscii() -> string",
    documentation:
      "Returns the string with ASCII characters converted to uppercase.",
  },
  {
    label: "replace",
    kind: "function",
    detail: "string.replace(old, new, [limit]) -> string",
    documentation:
      "Replaces occurrences of old with new. Optional limit restricts replacements.",
  },
  {
    label: "quote",
    kind: "function",
    detail: "strings.quote(string) -> string",
    documentation:
      "Returns the string with special characters escaped and wrapped in quotes.",
  },
];

// Map functions
export const celMapFunctions: CELCompletionItem[] = [
  {
    label: "size",
    kind: "function",
    detail: "map.size() -> int",
    documentation: "Returns the number of key-value pairs in the map.",
  },
];

// List functions
export const celListFunctions: CELCompletionItem[] = [
  {
    label: "size",
    kind: "function",
    detail: "list.size() -> int",
    documentation: "Returns the number of elements in the list.",
  },
  {
    label: "slice",
    kind: "function",
    detail: "list.slice(start, end) -> list",
    documentation:
      "Returns a sublist from start index to end index (exclusive).",
  },
  {
    label: "reverse",
    kind: "function",
    detail: "list.reverse() -> list",
    documentation: "Returns a new list with elements in reverse order.",
  },
  {
    label: "sort",
    kind: "function",
    detail: "list.sort() -> list",
    documentation:
      "Returns a new list with elements sorted in ascending order.",
  },
  {
    label: "sortBy",
    kind: "function",
    detail: "list.sortBy(var, expr) -> list",
    documentation:
      "Returns a new list sorted by the result of the expression applied to each element.",
    insertText: "${1:list}.sortBy(${2:x}, ${3:x.field})",
    insertTextRules: "insertAsSnippet",
  },
  {
    label: "first",
    kind: "function",
    detail: "list.first() -> T",
    documentation: "Returns the first element of the list.",
  },
  {
    label: "last",
    kind: "function",
    detail: "list.last() -> T",
    documentation: "Returns the last element of the list.",
  },
  {
    label: "distinct",
    kind: "function",
    detail: "list.distinct() -> list",
    documentation:
      "Returns a new list with duplicate elements removed, preserving order.",
  },
  {
    label: "flatten",
    kind: "function",
    detail: "list.flatten([depth]) -> list",
    documentation:
      "Flattens nested lists. Optional depth limits the recursion level.",
  },
];

// Timestamp functions
export const celTimestampFunctions: CELCompletionItem[] = [
  {
    label: "getDate",
    kind: "function",
    detail: "timestamp.getDate([timezone]) -> int",
    documentation: "Returns the day of the month (1-31) for the timestamp.",
  },
  {
    label: "getDayOfMonth",
    kind: "function",
    detail: "timestamp.getDayOfMonth([timezone]) -> int",
    documentation:
      "Returns the day of the month (0-30) for the timestamp. Zero-indexed variant.",
  },
  {
    label: "getDayOfWeek",
    kind: "function",
    detail: "timestamp.getDayOfWeek([timezone]) -> int",
    documentation:
      "Returns the day of the week (0=Sunday, 6=Saturday) for the timestamp.",
  },
  {
    label: "getDayOfYear",
    kind: "function",
    detail: "timestamp.getDayOfYear([timezone]) -> int",
    documentation: "Returns the day of the year (0-365) for the timestamp.",
  },
  {
    label: "getFullYear",
    kind: "function",
    detail: "timestamp.getFullYear([timezone]) -> int",
    documentation: "Returns the year for the timestamp.",
  },
  {
    label: "getHours",
    kind: "function",
    detail: "timestamp.getHours([timezone]) -> int",
    documentation: "Returns the hour (0-23) for the timestamp.",
  },
  {
    label: "getMilliseconds",
    kind: "function",
    detail: "timestamp.getMilliseconds([timezone]) -> int",
    documentation: "Returns the milliseconds (0-999) for the timestamp.",
  },
  {
    label: "getMinutes",
    kind: "function",
    detail: "timestamp.getMinutes([timezone]) -> int",
    documentation: "Returns the minutes (0-59) for the timestamp.",
  },
  {
    label: "getMonth",
    kind: "function",
    detail: "timestamp.getMonth([timezone]) -> int",
    documentation: "Returns the month (0-11) for the timestamp.",
  },
  {
    label: "getSeconds",
    kind: "function",
    detail: "timestamp.getSeconds([timezone]) -> int",
    documentation: "Returns the seconds (0-59) for the timestamp.",
  },
];

// Keywords
export const celKeywords: CELCompletionItem[] = [
  {
    label: "true",
    kind: "keyword",
    documentation: "Boolean true value.",
  },
  {
    label: "false",
    kind: "keyword",
    documentation: "Boolean false value.",
  },
  {
    label: "null",
    kind: "keyword",
    documentation: "Null value, represents the absence of a value.",
  },
  {
    label: "in",
    kind: "keyword",
    detail: "element in collection -> bool",
    documentation:
      "Tests membership in a list or map. For lists, tests element presence. For maps, tests key presence.",
  },
];

// Workshop custom functions
export const celWorkshopFunctions: CELCompletionItem[] = [
  {
    label: "require_touchid_with_cooldown_minutes",
    kind: "function",
    detail: "require_touchid_with_cooldown_minutes(minutes) -> REQUIRE_TOUCHID",
    documentation:
      "Returns REQUIRE_TOUCHID. The cooldown parameter specifies the number of minutes before TouchID is required again.",
    insertText: "require_touchid_with_cooldown_minutes(${1:minutes})",
    insertTextRules: "insertAsSnippet",
  },
  {
    label: "require_touchid_only_with_cooldown_minutes",
    kind: "function",
    detail:
      "require_touchid_only_with_cooldown_minutes(minutes) -> REQUIRE_TOUCHID_ONLY",
    documentation:
      "Returns REQUIRE_TOUCHID_ONLY. The cooldown parameter specifies the number of minutes before TouchID is required again.",
    insertText: "require_touchid_only_with_cooldown_minutes(${1:minutes})",
    insertTextRules: "insertAsSnippet",
  },
];

// Comprehension snippets
export const celComprehensionSnippets: CELCompletionItem[] = [
  {
    label: "all comprehension",
    kind: "snippet",
    detail: "Test if all elements satisfy a condition",
    documentation:
      "Example: numbers.all(n, n > 0) returns true if all numbers are positive.",
    insertText: "${1:list}.all(${2:item}, ${3:item > 0})",
    insertTextRules: "insertAsSnippet",
  },
  {
    label: "exists comprehension",
    kind: "snippet",
    detail: "Test if any element satisfies a condition",
    documentation:
      "Example: users.exists(u, u.admin) returns true if any user is an admin.",
    insertText: "${1:list}.exists(${2:item}, ${3:condition})",
    insertTextRules: "insertAsSnippet",
  },
  {
    label: "map comprehension",
    kind: "snippet",
    detail: "Transform each element in a list",
    documentation:
      "Example: numbers.map(n, n * 2) doubles each number in the list.",
    insertText: "${1:list}.map(${2:item}, ${3:item.field})",
    insertTextRules: "insertAsSnippet",
  },
  {
    label: "filter comprehension",
    kind: "snippet",
    detail: "Filter elements by condition",
    documentation:
      "Example: users.filter(u, u.active) returns only active users.",
    insertText: "${1:list}.filter(${2:item}, ${3:condition})",
    insertTextRules: "insertAsSnippet",
  },
  {
    label: "map then filter",
    kind: "snippet",
    detail: "Transform and filter a list",
    documentation:
      "Example: users.map(u, u.email).filter(e, e.endsWith('@example.com'))",
    insertText:
      "${1:list}.map(${2:item}, ${3:item.field}).filter(${4:x}, ${5:condition})",
    insertTextRules: "insertAsSnippet",
  },
  {
    label: "filter then map",
    kind: "snippet",
    detail: "Filter then transform a list",
    documentation:
      "Example: users.filter(u, u.active).map(u, u.name) gets names of active users.",
    insertText:
      "${1:list}.filter(${2:item}, ${3:condition}).map(${4:x}, ${5:x.field})",
    insertTextRules: "insertAsSnippet",
  },
  {
    label: "conditional expression",
    kind: "snippet",
    detail: "Ternary conditional (? :)",
    documentation:
      "Evaluates to the first expression if condition is true, otherwise the second.",
    insertText: "${1:condition} ? ${2:trueValue} : ${3:falseValue}",
    insertTextRules: "insertAsSnippet",
  },
  {
    label: "has field check",
    kind: "snippet",
    detail: "Check if a field is present",
    documentation: "Tests whether a message field is set or a map key exists.",
    insertText: "has(${1:object}.${2:field})",
    insertTextRules: "insertAsSnippet",
  },
];

// All completion items combined
export const allCELCompletions: CELCompletionItem[] = [
  ...celMacros,
  ...celMapFunctions,
  ...celStringFunctions,
  ...celListFunctions,
  ...celTimestampFunctions,
  ...celWorkshopFunctions,
  ...celKeywords,
  ...celComprehensionSnippets,
];

export const celLanguageDefinition = {
  // Set default token type
  defaultToken: "",
  tokenPostfix: ".cel",

  // Keywords
  keywords: ["true", "false", "null", "in"],

  // Macros (expanded at parse time)
  macros: ["has", "all", "exists", "exists_one", "map", "filter"],

  // Built-in functions
  builtins: [
    // Core functions
    "size",
    "type",
    "dyn",
    // Type conversions
    "string",
    "bytes",
    "int",
    "uint",
    "double",
    "bool",
    "duration",
    "timestamp",
    // String methods
    "startsWith",
    "endsWith",
    "contains",
    "matches",
    "charAt",
    "indexOf",
    "lastIndexOf",
    "join",
    "split",
    "substring",
    "trim",
    "lowerAscii",
    "upperAscii",
    "replace",
    "quote",
    // List methods
    "slice",
    "reverse",
    "sort",
    "sortBy",
    "first",
    "last",
    "distinct",
    "flatten",
    // Timestamp methods
    "getDate",
    "getDayOfMonth",
    "getDayOfWeek",
    "getDayOfYear",
    "getFullYear",
    "getHours",
    "getMilliseconds",
    "getMinutes",
    "getMonth",
    "getSeconds",
    // Workshop custom functions
    "require_touchid_with_cooldown_minutes",
    "require_touchid_only_with_cooldown_minutes",
  ],

  // Operators (CEL-specific, no assignment operators)
  operators: [
    // Comparison
    "==",
    "!=",
    "<",
    ">",
    "<=",
    ">=",
    // Logical
    "&&",
    "||",
    "!",
    // Arithmetic
    "+",
    "-",
    "*",
    "/",
    "%",
    // Ternary
    "?",
    ":",
    // Index/field access
    ".",
  ],

  // Common regular expressions
  symbols: /[=><!~?:&|+\-*/^%]+/,
  escapes:
    /\\(?:[abfnrtv\\"']|x[0-9A-Fa-f]{1,4}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})/,
  digits: /\d+(_+\d+)*/,
  octaldigits: /[0-7]+(_+[0-7]+)*/,
  binarydigits: /[0-1]+(_+[0-1]+)*/,
  hexdigits: /[[0-9a-fA-F]+(_+[0-9a-fA-F]+)*/,

  // Tokenizer
  tokenizer: {
    root: [
      // Identifiers and keywords
      [
        /[a-zA-Z_$][\w$]*/,
        {
          cases: {
            "@keywords": "keyword",
            "@macros": "keyword",
            "@builtins": "predefined",
            "@default": "identifier",
          },
        },
      ],

      // Whitespace
      { include: "@whitespace" },

      // Delimiters and operators
      [/[{}()[\]]/, "@brackets"],
      [/[<>](?!@symbols)/, "@brackets"],
      [
        /@symbols/,
        {
          cases: {
            "@operators": "operator",
            "@default": "",
          },
        },
      ],

      // Numbers
      [/(@digits)[eE]([-+]?(@digits))?[fFdD]?/, "number.float"],
      [/(@digits)\.(@digits)([eE][-+]?(@digits))?[fFdD]?/, "number.float"],
      [/0[xX](@hexdigits)[Ll]?/, "number.hex"],
      [/0(@octaldigits)[Ll]?/, "number.octal"],
      [/0[bB](@binarydigits)[Ll]?/, "number.binary"],
      [/(@digits)[fFdD]/, "number.float"],
      [/(@digits)[lL]?/, "number"],

      // Delimiter: after number because of .\d floats
      [/[;,.]/, "delimiter"],

      // Strings
      [/"([^"\\]|\\.)*$/, "string.invalid"], // non-terminated string
      [/"/, "string", "@string_double"],
      [/'([^'\\]|\\.)*$/, "string.invalid"], // non-terminated string
      [/'/, "string", "@string_single"],
      [/`/, "string", "@string_backtick"],

      // Characters
      [/'[^\\']'/, "string"],
      [/(')(@escapes)(')/, ["string", "string.escape", "string"]],
      [/'/, "string.invalid"],
    ],

    whitespace: [
      [/[ \t\r\n]+/, ""],
      [/\/\*\*(?!\/)/, "comment.doc", "@doccomment"],
      [/\/\*/, "comment", "@comment"],
      [/\/\/.*$/, "comment"],
    ],

    comment: [
      [/[^/*]+/, "comment"],
      [/\*\//, "comment", "@pop"],
      [/[/*]/, "comment"],
    ],

    doccomment: [
      [/[^/*]+/, "comment.doc"],
      [/\*\//, "comment.doc", "@pop"],
      [/[/*]/, "comment.doc"],
    ],

    string_double: [
      [/[^\\"]+/, "string"],
      [/@escapes/, "string.escape"],
      [/\\./, "string.escape.invalid"],
      [/"/, "string", "@pop"],
    ],

    string_single: [
      [/[^\\']+/, "string"],
      [/@escapes/, "string.escape"],
      [/\\./, "string.escape.invalid"],
      [/'/, "string", "@pop"],
    ],

    string_backtick: [
      [/[^\\`]+/, "string"],
      [/@escapes/, "string.escape"],
      [/\\./, "string.escape.invalid"],
      [/`/, "string", "@pop"],
    ],
  },
};

// Map CEL completion kinds to Monaco completion kinds
function getMonacoKind(monaco: any, kind: CELCompletionItem["kind"]) {
  switch (kind) {
    case "keyword":
      return monaco.languages.CompletionItemKind.Keyword;
    case "function":
      return monaco.languages.CompletionItemKind.Function;
    case "snippet":
      return monaco.languages.CompletionItemKind.Snippet;
    case "type":
      return monaco.languages.CompletionItemKind.Class;
    case "macro":
      return monaco.languages.CompletionItemKind.Keyword;
    default:
      return monaco.languages.CompletionItemKind.Text;
  }
}

// Variable type for context-aware completions
export type CELVariableType =
  | "list"
  | "string"
  | "map"
  | "timestamp"
  | "duration"
  | "int"
  | "uint"
  | "double"
  | "bool"
  | "bytes";

export interface CELVariable {
  name: string;
  type: CELVariableType;
  documentation?: string;
}

// Track registration state to prevent duplicate registrations
let celLanguageRegistered = false;
let completionProviderDisposable: { dispose: () => void } | null = null;

// Register the CEL language with Monaco
// This function should be called in the beforeMount callback of
// @monaco-editor/react
export function registerCELLanguage(
  monaco: any,
  options?: {
    // Include built-in CEL completions (macros, functions, etc.)
    includeCELCompletions?: boolean;
    // Variables with type information for context-aware completions
    variables?: CELVariable[];
  },
) {
  const { includeCELCompletions = true, variables = [] } = options || {};

  // Register the language, tokens provider, and configuration only once
  if (!celLanguageRegistered) {
    monaco.languages.register({ id: "cel" });
    monaco.languages.setMonarchTokensProvider("cel", celLanguageDefinition);
    monaco.languages.setLanguageConfiguration("cel", {
      comments: {
        lineComment: "//",
        blockComment: ["/*", "*/"],
      },
      brackets: [
        ["{", "}"],
        ["[", "]"],
        ["(", ")"],
      ],
      autoClosingPairs: [
        { open: "{", close: "}" },
        { open: "[", close: "]" },
        { open: "(", close: ")" },
        { open: '"', close: '"', notIn: ["string"] },
        { open: "'", close: "'", notIn: ["string", "comment"] },
        { open: "`", close: "`", notIn: ["string", "comment"] },
        { open: "/**", close: " */", notIn: ["string"] },
      ],
      surroundingPairs: [
        { open: "{", close: "}" },
        { open: "[", close: "]" },
        { open: "(", close: ")" },
        { open: '"', close: '"' },
        { open: "'", close: "'" },
        { open: "`", close: "`" },
      ],
      folding: {
        markers: {
          start: new RegExp("^\\s*//\\s*#?region\\b"),
          end: new RegExp("^\\s*//\\s*#?endregion\\b"),
        },
      },
    });
    celLanguageRegistered = true;
  }

  // Dispose previous completion provider before registering a new one
  if (completionProviderDisposable) {
    completionProviderDisposable.dispose();
    completionProviderDisposable = null;
  }

  // Build a map of variable names to types for quick lookup
  const variableTypes = new Map<string, CELVariableType>();
  variables.forEach((v) => variableTypes.set(v.name, v.type));

  // Build general completion items (not after a dot)
  const generalCompletions: any[] = [];

  // Add typed variables
  variables.forEach((variable) => {
    generalCompletions.push({
      label: variable.name,
      kind: monaco.languages.CompletionItemKind.Variable,
      insertText: variable.name,
      detail: variable.type,
      documentation:
        variable.documentation || `Variable of type ${variable.type}`,
    });
  });

  // Add built-in CEL completions if enabled
  if (includeCELCompletions) {
    allCELCompletions.forEach((item) => {
      const completion: any = {
        label: item.label,
        kind: getMonacoKind(monaco, item.kind),
        insertText: item.insertText || item.label,
        detail: item.detail,
        documentation: item.documentation
          ? { value: item.documentation }
          : undefined,
      };

      if (item.insertTextRules === "insertAsSnippet") {
        completion.insertTextRules =
          monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet;
      }

      generalCompletions.push(completion);
    });
  }

  // Build method completions for each type
  const mapMethodCompletions = celMapFunctions.map((item) => {
    const completion: any = {
      label: item.label,
      kind: getMonacoKind(monaco, item.kind),
      insertText: item.insertText || item.label,
      detail: item.detail,
      documentation: item.documentation
        ? { value: item.documentation }
        : undefined,
    };
    if (item.insertTextRules === "insertAsSnippet") {
      completion.insertTextRules =
        monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet;
    }
    return completion;
  });

  // Add map-compatible macros (all, exists, exists_one iterate over keys)
  celMacros
    .filter((m) => ["all", "exists", "exists_one"].includes(m.label))
    .forEach((item) => {
      mapMethodCompletions.push({
        label: item.label,
        kind: getMonacoKind(monaco, item.kind),
        insertText: item.label,
        detail: item.detail,
        documentation: item.documentation
          ? { value: item.documentation }
          : undefined,
      });
    });

  const listMethodCompletions = celListFunctions.map((item) => {
    const completion: any = {
      label: item.label,
      kind: getMonacoKind(monaco, item.kind),
      insertText: item.insertText || item.label,
      detail: item.detail,
      documentation: item.documentation
        ? { value: item.documentation }
        : undefined,
    };
    if (item.insertTextRules === "insertAsSnippet") {
      completion.insertTextRules =
        monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet;
    }
    return completion;
  });

  // Add list macros (all, exists, exists_one, map, filter) to list methods
  celMacros
    .filter((m) => m.label !== "has")
    .forEach((item) => {
      const completion: any = {
        label: item.label,
        kind: getMonacoKind(monaco, item.kind),
        // For methods, strip the list prefix from snippets like "${1:list}.all(...)"
        insertText: item.label,
        detail: item.detail,
        documentation: item.documentation
          ? { value: item.documentation }
          : undefined,
      };
      listMethodCompletions.push(completion);
    });

  const stringMethodCompletions = celStringFunctions.map((item) => {
    const completion: any = {
      label: item.label,
      kind: getMonacoKind(monaco, item.kind),
      insertText: item.insertText || item.label,
      detail: item.detail,
      documentation: item.documentation
        ? { value: item.documentation }
        : undefined,
    };
    if (item.insertTextRules === "insertAsSnippet") {
      completion.insertTextRules =
        monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet;
    }
    return completion;
  });

  const timestampMethodCompletions = celTimestampFunctions.map((item) => {
    const completion: any = {
      label: item.label,
      kind: getMonacoKind(monaco, item.kind),
      insertText: item.insertText || item.label,
      detail: item.detail,
      documentation: item.documentation
        ? { value: item.documentation }
        : undefined,
    };
    if (item.insertTextRules === "insertAsSnippet") {
      completion.insertTextRules =
        monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet;
    }
    return completion;
  });

  // Register completion provider with context awareness
  completionProviderDisposable =
    monaco.languages.registerCompletionItemProvider("cel", {
      triggerCharacters: ["."],
      provideCompletionItems: (model: any, position: any) => {
        const textUntilPosition = model.getValueInRange({
          startLineNumber: position.lineNumber,
          startColumn: 1,
          endLineNumber: position.lineNumber,
          endColumn: position.column,
        });

        // Check if we're typing after a dot (e.g., "args." or "target.signing_time.")
        // Captures the full dotted path before the final dot
        const dotMatch = textUntilPosition.match(
          /([\w]+(?:\.[\w]+)*)\.[\w]*$/,
        );
        if (dotMatch) {
          const varPath = dotMatch[1];
          const varType = variableTypes.get(varPath);

          // Check for sub-field completions (e.g., "target." → "signing_time")
          const prefix = varPath + ".";
          const fieldCompletions: any[] = [];
          const seenFields = new Set<string>();

          for (const [name] of variableTypes) {
            if (name.startsWith(prefix)) {
              const rest = name.slice(prefix.length);
              const nextSegment = rest.split(".")[0];
              if (!seenFields.has(nextSegment)) {
                seenFields.add(nextSegment);
                const fullFieldName = prefix + nextSegment;
                const matchingVar = variables.find(
                  (v) => v.name === fullFieldName,
                );
                fieldCompletions.push({
                  label: nextSegment,
                  kind: monaco.languages.CompletionItemKind.Field,
                  insertText: nextSegment,
                  detail: matchingVar?.type || "field",
                  documentation: matchingVar?.documentation,
                });
              }
            }
          }

          // Return type-specific methods combined with any field completions
          if (varType === "map") {
            return {
              suggestions: [...fieldCompletions, ...mapMethodCompletions],
            };
          } else if (varType === "list") {
            return {
              suggestions: [...fieldCompletions, ...listMethodCompletions],
            };
          } else if (varType === "string") {
            return {
              suggestions: [...fieldCompletions, ...stringMethodCompletions],
            };
          } else if (varType === "timestamp") {
            return {
              suggestions: [...fieldCompletions, ...timestampMethodCompletions],
            };
          } else if (varType) {
            // Known type without specific method completions (int, bool, etc.)
            return { suggestions: fieldCompletions };
          }

          // No type info: return fields if any, otherwise all methods as fallback
          if (fieldCompletions.length > 0) {
            return { suggestions: fieldCompletions };
          }
          return {
            suggestions: [
              ...mapMethodCompletions,
              ...listMethodCompletions,
              ...stringMethodCompletions,
              ...timestampMethodCompletions,
            ],
          };
        }

        return { suggestions: generalCompletions };
      },
    });
}
