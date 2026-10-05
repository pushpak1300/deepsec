import type { MatcherPlugin } from "../types.js";
import { isLaravelSkippablePath } from "./laravel-utils.js";
import { regexMatcher } from "./utils.js";

const RAW_METHODS =
  "whereRaw|orWhereRaw|havingRaw|orHavingRaw|orderByRaw|groupByRaw|selectRaw|fromRaw|joinRaw";
const TAINTED_ARG = String.raw`(?:"[^"]*\$|(?:'[^']*'|"[^"]*")\s*\.\s*\$|\$)`;
const REQ = String.raw`(?:\$request->|request\s*\(\s*\)->)`;

/**
 * Laravel query-builder and DB-facade raw SQL with interpolated input, plus
 * request-controlled column names (bindings can't parameterize identifiers).
 */
export const laravelSqlRawMatcher: MatcherPlugin = {
  noiseTier: "precise" as const,
  slug: "laravel-sql-raw",
  description:
    "Laravel raw SQL (*Raw helpers, DB::statement/select/...) with interpolation, and request-controlled column names",
  filePatterns: ["**/app/**/*.php", "**/routes/**/*.php"],
  requires: { tech: ["laravel"] },
  examples: [
    `User::whereRaw("name = '$name'")->get();`,
    `$q->orderByRaw('FIELD(id, ' . $ids . ')');`,
    `$q->selectRaw($expr);`,
    `DB::select("SELECT * FROM users WHERE id = $id");`,
    `DB::statement('DROP TABLE ' . $table);`,
    `DB::raw($sql)`,
    `$q->orderBy($request->input('sort'));`,
    `$q->pluck(request()->query('col'));`,
    `$q->where($request->input('field'), $request->input('value'));`,
  ],
  match(content, filePath) {
    if (isLaravelSkippablePath(filePath)) return [];
    return regexMatcher(
      "laravel-sql-raw",
      [
        {
          regex: new RegExp(String.raw`\b(?:${RAW_METHODS})\s*\(\s*${TAINTED_ARG}`),
          label: "*Raw query helper with interpolated/variable SQL (SQL injection)",
        },
        {
          regex:
            /\bDB::(?:raw|statement|select|insert|update|delete|unprepared)\s*\(\s*(?:"[^"]*\$|(?:'[^']*'|"[^"]*")\s*\.\s*\$|\$\w+\s*[,)])/,
          label: "DB facade raw SQL with interpolated/variable SQL (SQL injection)",
        },
        {
          regex: new RegExp(
            String.raw`->(?:orderBy|orderByDesc|groupBy|pluck|value|whereColumn|select)\s*\(\s*${REQ}`,
          ),
          label: "Request-controlled column/identifier (SQL injection; bindings don't apply)",
        },
        {
          regex: new RegExp(String.raw`->where\s*\(\s*${REQ}(?:input|get|query)\s*\(`),
          label: "Request-controlled where() column name",
        },
      ],
      content,
    );
  },
};
