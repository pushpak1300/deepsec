import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";
import { hasAuthMarker, isLaravelSkippablePath } from "./laravel-utils.js";
import { regexMatcher } from "./utils.js";

const MUTATING_ACTION = /public\s+function\s+(?:store|update|destroy|delete|edit|create)\s*\(/;

/**
 * File-level check: a controller with
 * mutating actions and no authorization marker anywhere in the file. Route
 * middleware lives elsewhere, so this is a lead to verify, not a verdict.
 */
export const laravelMissingAuthorizationMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "laravel-missing-authorization",
  description:
    "Laravel controllers with mutating actions and no in-file authorization; routes that drop middleware",
  filePatterns: ["**/app/Http/Controllers/**/*.php", "**/routes/**/*.php"],
  requires: { tech: ["laravel"] },
  examples: [
    `class PostController extends Controller {\n  public function destroy(Post $post) {\n    $post->delete();\n  }\n}`,
    `Route::get('/export', ExportController::class)->withoutMiddleware('auth');`,
    `Route::fallback(function () { return view('404'); });`,
  ],
  match(content, filePath) {
    if (isLaravelSkippablePath(filePath)) return [];

    const matches: CandidateMatch[] = [];
    if (!hasAuthMarker(content)) {
      const lines = content.split("\n");
      const hits = lines.flatMap((l, i) => (MUTATING_ACTION.test(l) ? [i + 1] : []));
      if (hits.length > 0) {
        matches.push({
          vulnSlug: "laravel-missing-authorization",
          lineNumbers: hits,
          snippet: lines.slice(Math.max(0, hits[0] - 2), hits[0] + 3).join("\n"),
          matchedPattern:
            "Mutating controller action with no in-file authorization (check route middleware and FormRequest)",
        });
      }
    }
    return matches.concat(
      regexMatcher(
        "laravel-missing-authorization",
        [
          {
            regex: /->withoutMiddleware\s*\(/,
            label: "withoutMiddleware (confirm the removed middleware isn't auth/CSRF)",
          },
          { regex: /\bRoute::fallback\s*\(/, label: "Route::fallback (informational)" },
        ],
        content,
      ),
    );
  },
};
