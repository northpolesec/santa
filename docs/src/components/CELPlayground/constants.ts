export const VARIABLES = ["target", "args", "envs", "euid", "cwd"] as const;

export const DYNAMIC_FIELDS = ["args", "envs", "euid", "cwd"] as const;

export const V2_ONLY_FUNCTIONS = [
  "require_touchid_with_cooldown_minutes",
  "require_touchid_only_with_cooldown_minutes",
] as const;

export const FUNCTIONS = ["timestamp", ...V2_ONLY_FUNCTIONS] as const;
