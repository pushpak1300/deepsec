export function isLaravelSkippablePath(filePath: string): boolean {
  return /(?:^|\/)(?:tests?|vendor)\/|(?:^|\/)database\/(?:migrations|seeders|factories)\//.test(
    filePath,
  );
}

/**
 * Any in-file sign of authorization: gates, policies, `can:`/`auth`
 * middleware, authorize() calls, or a FormRequest type-hint (FormRequest
 * `authorize()` runs before the action). A plain `Request $r` does not count.
 */
const AUTH_MARKER =
  /\bauthorize\w*\s*\(|\bGate::|->(?:can|cannot)\s*\(|\bauthorizeResource\b|\bPolicy\b|\bmiddleware\s*\(\s*['"](?:can:|auth)|#\[Authorize|\babort_(?:if|unless)\s*\(|\bHasMiddleware\b|\b(?!Request\b)\w+Request\s+\$/;

export function hasAuthMarker(content: string): boolean {
  return AUTH_MARKER.test(content);
}
