import type { MatcherPlugin } from "../types.js";
import { regexMatcher } from "./utils.js";

/**
 * Laravel misconfiguration: debug mode, committed secrets, weak cookie/CORS
 * settings, open dashboards, and CSRF/signed-URL exemptions.
 */
export const laravelConfigExposureMatcher: MatcherPlugin = {
  noiseTier: "normal" as const,
  slug: "laravel-config-exposure",
  description:
    "Laravel misconfiguration — APP_DEBUG, committed secrets, weak cookie/CORS settings, open dashboards, CSRF exemptions",
  filePatterns: [
    "**/config/*.php",
    "**/.env",
    "**/.env.*",
    "**/bootstrap/app.php",
    "**/app/Http/Middleware/*.php",
    "**/app/Providers/*ServiceProvider.php",
    "**/routes/**/*.php",
  ],
  requires: { tech: ["laravel"] },
  examples: [
    `APP_DEBUG=true`,
    `APP_KEY=base64:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG=`,
    `DB_PASSWORD=hunter2`,
    `'debug' => true,`,
    `'key' => 'abcdefghijklmnop1234',`,
    `'secure' => false,`,
    `'http_only' => false,`,
    `'same_site' => 'none',`,
    `'allowed_origins' => ['*'],`,
    `'supports_credentials' => true,`,
    `Gate::define('viewTelescope', fn ($user = null) => true);`,
    `Gate::define('viewHorizon', function ($user) {`,
    `->validateCsrfTokens(except: ['stripe/*']);`,
    `protected $except = ['webhook/*'];`,
    `Route::post('/hook', $h)->withoutMiddleware([VerifyCsrfToken::class]);`,
    `abort_unless($request->hasValidSignature(), 403);`,
  ],
  match(content, filePath) {
    if (/\.env\.(?:example|sample|dist)$/.test(filePath) || /(?:^|\/)vendor\//.test(filePath))
      return [];
    return regexMatcher(
      "laravel-config-exposure",
      [
        {
          regex: /^\s*APP_DEBUG\s*=\s*["']?true/i,
          label: "APP_DEBUG=true (stack traces / env leak)",
        },
        {
          regex: /^\s*APP_KEY\s*=\s*base64:\S{20,}/,
          label: "Committed APP_KEY (forges sessions/cookies, decrypts data)",
        },
        {
          regex:
            /^\s*(?:DB_PASSWORD|AWS_SECRET_ACCESS_KEY|STRIPE_SECRET|MAIL_PASSWORD|REDIS_PASSWORD)\s*=\s*["']?[^\s"'#]/,
          label: "Committed secret in .env",
        },
        { regex: /['"]debug['"]\s*=>\s*true\b/, label: "'debug' => true hardcoded" },
        {
          regex: /['"](?:key|secret|password)['"]\s*=>\s*['"][^'"]{8,}['"]/,
          label: "Hardcoded key/secret in config",
        },
        { regex: /['"]secure['"]\s*=>\s*false\b/, label: "Session cookie 'secure' => false" },
        { regex: /['"]http_only['"]\s*=>\s*false\b/, label: "Session cookie 'http_only' => false" },
        {
          regex: /['"]same_site['"]\s*=>\s*(?:null|['"]none['"])/i,
          label: "Session cookie same_site null/none (CSRF exposure)",
        },
        {
          regex: /['"]allowed_origins['"]\s*=>\s*\[\s*['"]\*['"]/,
          label: "CORS allowed_origins wildcard (dangerous with supports_credentials)",
        },
        {
          regex: /['"]supports_credentials['"]\s*=>\s*true\b/,
          label: "CORS supports_credentials true (check allowed_origins)",
        },
        {
          regex:
            /Gate::define\s*\(\s*['"]view(?:Telescope|Horizon|Pulse)['"].*(?:=>|return)\s*true\b/,
          label: "Telescope/Horizon/Pulse dashboard open to everyone",
        },
        {
          regex: /Gate::define\s*\(\s*['"]view(?:Telescope|Horizon|Pulse)['"]/,
          label: "Dashboard gate (informational — confirm it is not open)",
        },
        {
          regex: /validateCsrfTokens\s*\(\s*except\s*:/,
          label: "validateCsrfTokens except (CSRF exemption)",
        },
        {
          regex: /\$except\s*=\s*\[/,
          label: "Middleware $except list (CSRF/encryption/trim exemptions)",
        },
        {
          regex: /->withoutMiddleware\s*\(.*(?:VerifyCsrfToken|['"]web['"])/,
          label: "Route drops CSRF/web middleware",
        },
        {
          regex: /->hasValid(?:Relative)?Signature(?:While)?\s*\(/,
          label: "Signed URL check (informational — confirm it guards the action)",
        },
      ],
      content,
    );
  },
};
