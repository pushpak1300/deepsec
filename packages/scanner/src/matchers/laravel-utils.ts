export function isLaravelSkippablePath(filePath: string): boolean {
  return /(?:^|\/)(?:tests?|vendor)\/|(?:^|\/)database\/(?:migrations|seeders|factories)\//.test(
    filePath,
  );
}

/**
 * Any sign of authorization: gates, `can:`/`auth` middleware, authorize()
 * calls, or a FormRequest type-hint (FormRequest `authorize()` runs before
 * the action). A plain `Request $r` does not count.
 */
const AUTH_MARKER =
  /\bauthorize\w*\s*\(|\bGate::|->(?:can|cannot)\s*\(|\bauthorizeResource\b|\bmiddleware\s*\(\s*['"](?:can:|auth)|#\[Authorize|\babort_(?:if|unless)\s*\(|\bHasMiddleware\b|\b(?!Request\b)\w+Request\s+\$/;

export function hasAuthMarker(content: string): boolean {
  return AUTH_MARKER.test(content);
}

const CLASS_AUTH = /\bauthorizeResource\b|\bHasMiddleware\b|\$this->middleware\s*\(/;
const FUNCTION_DECL = /\bfunction\s+\w+\s*\(/;

/**
 * 1-based lines of `action` methods whose own body has no authorization, so
 * an authorized store() can't hide an unprotected destroy(). A method body
 * runs until the next named function.
 */
export function unauthorizedActions(content: string, action: RegExp): number[] {
  if (CLASS_AUTH.test(content)) return [];
  const lines = content.split("\n");
  return lines.flatMap((line, i) => {
    if (!action.test(line)) return [];
    let end = i + 1;
    while (end < lines.length && !FUNCTION_DECL.test(lines[end])) end++;
    return hasAuthMarker(lines.slice(i, end).join("\n")) ? [] : [i + 1];
  });
}
