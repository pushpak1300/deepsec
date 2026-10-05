import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";
import { hasAuthMarker, isLaravelSkippablePath, unauthorizedActions } from "./laravel-utils.js";
import { regexMatcher } from "./utils.js";

const IDENTITY_PROP =
  /^\s*public\s+(?:\??(?:int|string|[A-Z]\w*)\s+)?\$(?:\w*Id|id|\w*_id|user|post|team|order|account)\b/;
const ACTION =
  /public\s+function\s+(?:delete|update|save|destroy|remove|approve|publish|impersonate)\w*\s*\(/;
const RESOURCE_AUTH = /\bcan(?:ViewAny|View|Create|Edit|Delete)\b|\bauthorizedTo\w+/;

/**
 * Livewire/Filament/Nova: public component properties are client-writable
 * and actions are public endpoints; admin Resources default to policy
 * auto-discovery, which silently allows everything when no policy exists.
 */
export const laravelLivewireFilamentMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "laravel-livewire-filament",
  description:
    "Livewire/Filament/Nova — unlocked identity properties, actions without authorization, Resources without policies, ->html() columns",
  filePatterns: [
    "**/app/Livewire/**/*.php",
    "**/app/Http/Livewire/**/*.php",
    "**/app/Filament/**/*.php",
    "**/app/Nova/**/*.php",
  ],
  requires: { tech: ["laravel"] },
  examples: [
    `class EditPost extends Component {\n  public int $postId;\n  public function delete() { Post::find($this->postId)->delete(); }\n}`,
    `class PostResource extends Resource { protected static ?string $model = Post::class; }`,
    `TextColumn::make('body')->html();`,
  ],
  match(content, filePath) {
    if (isLaravelSkippablePath(filePath)) return [];

    const lines = content.split("\n");
    const matches: CandidateMatch[] = [];
    const add = (hits: number[], label: string) => {
      if (hits.length === 0) return;
      matches.push({
        vulnSlug: "laravel-livewire-filament",
        lineNumbers: hits,
        snippet: lines.slice(Math.max(0, hits[0] - 2), hits[0] + 3).join("\n"),
        matchedPattern: label,
      });
    };
    const find = (re: RegExp, skip?: (i: number) => boolean) =>
      lines.flatMap((l, i) => (re.test(l) && !skip?.(i) ? [i + 1] : []));

    if (/extends\s+(?:\\?Livewire\\)?Component\b|\bLivewire\\/.test(content)) {
      add(
        find(
          IDENTITY_PROP,
          (i) => /#\[Locked/.test(lines[i]) || /#\[Locked/.test(lines[i - 1] ?? ""),
        ),
        "Public Livewire property is client-writable (add #[Locked] and re-authorize)",
      );
      add(
        unauthorizedActions(content, ACTION),
        "Livewire action with no authorization (public endpoint)",
      );
    }
    if (
      /class\s+\w+\s+extends\s+Resource\b/.test(content) &&
      !hasAuthMarker(content) &&
      !RESOURCE_AUTH.test(content)
    ) {
      add(
        find(/class\s+\w+\s+extends\s+Resource\b/),
        "Admin Resource without policy/can*() overrides (verify a policy exists)",
      );
    }
    return matches.concat(
      regexMatcher(
        "laravel-livewire-filament",
        [{ regex: /->html\s*\(\s*\)/, label: "->html() column renders unescaped HTML (XSS)" }],
        content,
      ),
    );
  },
};
