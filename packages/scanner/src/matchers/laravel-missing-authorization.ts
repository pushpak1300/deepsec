import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";
import { isLaravelSkippablePath, unauthorizedActions } from "./laravel-utils.js";
import { regexMatcher } from "./utils.js";

const MUTATING_ACTION = /public\s+function\s+(?:store|update|destroy|delete|edit|create)\s*\(/;

/**
 * Per-action check: a controller action that mutates and has no
 * authorization in its own body. Route middleware lives elsewhere, so this
 * is a lead to verify, not a verdict.
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
    const hits = unauthorizedActions(content, MUTATING_ACTION);
    if (hits.length > 0) {
      const lines = content.split("\n");
      matches.push({
        vulnSlug: "laravel-missing-authorization",
        lineNumbers: hits,
        snippet: lines.slice(Math.max(0, hits[0] - 2), hits[0] + 3).join("\n"),
        matchedPattern:
          "Mutating controller action with no authorization (check route middleware and FormRequest)",
      });
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
