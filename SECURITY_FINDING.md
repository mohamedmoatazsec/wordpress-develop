# Security Finding

> **STATUS UPDATE (impact validation, supersedes the conclusion below): NOT EXPLOITABLE / FALSE POSITIVE.**
> Runtime testing on WordPress 7.1.2 with Chromium (Playwright 1.56) proves the smuggled `}`
> does **not** break out of the CSS rule in a real browser. `safecss_filter_attr()` only lets a
> `}` survive when it is **inside** a CSS function's `(...)`, and per the CSS Syntax spec a `}`
> inside `(...)` is consumed as part of the declaration value — it never terminates the rule.
> The browser dropped the invalid declaration and created **no** attacker-controlled rule; the
> attacker server received **zero** requests. There is no stored CSS injection, no exfiltration,
> and no security-boundary crossing. See the "IMPACT VALIDATION" section at the end for the
> evidence. The technical write-up below is retained as-is for the record but its impact claim
> is withdrawn.

## Stored CSS injection via block "state styles" — `safecss_filter_attr()` allows `}` inside CSS functions, breaking out of generated stylesheet rules

### Summary
A user **without the `unfiltered_html` capability** (e.g. the default **Author** role on
single‑site; any non‑super‑admin on multisite) can store arbitrary CSS rules that are
emitted, verbatim, into a front‑end `<style>` element rendered for every visitor.

The sanitizer that is supposed to prevent this, `safecss_filter_attr()`, only checks a
*modified* copy of the value (with allowed CSS functions stripped out) for the forbidden
characters `\ ( & = } /*`, while the *original, unmodified* value is what gets written to
the output. Any forbidden character placed **inside the parentheses of an allowed CSS
function** (e.g. `rotate(...)`, `calc(...)`, `var(...)`, `linear-gradient(...)`) therefore
survives. When the surviving character is `}` and the value is used in a **stylesheet
context** (a CSS rule block `selector{ ... }`, as opposed to an inline `style="..."`
attribute), the `}` closes the rule early and lets the attacker inject a new, fully
attacker‑controlled CSS rule.

The block **state styles** feature added in 7.1 (`wp-includes/block-supports/states.php`)
is a directly reachable stylesheet sink: it takes arbitrary values out of a block's
`style` attribute (e.g. `style[':hover']['color']['text']`), runs them through the style
engine (which calls `safecss_filter_attr()`), and emits the result as a real CSS rule via
`wp_style_engine_get_stylesheet_from_css_rules()`.

### Security boundary violated
`safecss_filter_attr()` is the boundary that stops users lacking `unfiltered_html` /
`edit_css` from injecting raw CSS into content that is rendered to other users. Authors and
Contributors never hold `unfiltered_html`; on multisite, neither do Editors or
Administrators. This finding lets those users bypass that boundary and store CSS that runs
in every visitor's browser (including administrators viewing the post on the front end).

### Impact
Stored CSS injection (not JavaScript execution). Realistic consequences:
- Exfiltration of data present in DOM attributes via attribute‑selector + `background:url()`
  requests to an attacker host (the PoC below already injects an external `url()`).
- Site‑wide UI redressing / defacement / phishing overlays, hiding admin or security
  notices, spoofing content.
Constraint: because `;` is a declaration separator consumed earlier in the sanitizer, each
injected rule holds a single declaration — but an unlimited number of single‑declaration
rules can be injected (`.a{...}.b{...}...`), which is sufficient for the above.

Severity: Medium (authenticated, low‑privilege actor; persistent; affects all visitors;
CSS‑only, not script execution).

---

### Exact source locations

**1. Root cause — `safecss_filter_attr()`**
`src/wp-includes/kses.php` (lines ~3027–3078). The allowed‑function stripping builds
`$css_test_string`, and the final safety check runs against that stripped string, while the
value appended to the output is the original `$css_item`:

```php
// Allowed functions (incl. 7.1 additions: transform/shape fns) are stripped from the TEST string.
$css_test_string = preg_replace(
    '/\b(?:var|calc|min|max|minmax|clamp|repeat'
    . '|matrix|matrix3d|perspective|rotate|rotate3d|rotateX|rotateY|rotateZ'
    . '|scale|scale3d|scaleX|scaleY|scaleZ|skew|skewX|skewY'
    . '|translate|translate3d|translateX|translateY|translateZ'
    . '|circle|ellipse|inset|path|polygon|rect|shape|xywh'
    . ')(\((?:[^()]|(?1))*\))/',
    '',
    $css_test_string
);
...
// Forbidden chars are checked on the STRIPPED string only:
$allow_css = 0 === preg_match( '%[\\\(&=}]|/\*%', $css_test_string );
...
if ( $allow_css ) {
    ...
    $css .= $css_item;   // <-- ORIGINAL value (with the smuggled `}`) is emitted.
}
```
Gradient stripping (line ~3014) and `url()` stripping (line ~2985) create the same gap for
`-gradient(...)` and `url(...)`.

**2. Reachable stylesheet sink — block state styles (7.1)**
- `src/wp-includes/block-supports/states.php`
  - `wp_render_block_states_support()` (hooked on `render_block`) reads `$block['attrs']['style'][':hover']` etc.
  - `wp_add_block_state_style_rule()` → `wp_style_engine_get_styles()` and then
    `WP_Style_Engine_CSS_Declarations::add_declaration()`.
  - Final emission via `wp_style_engine_get_stylesheet_from_css_rules( $style_rules, [ 'context' => 'block-supports' ] )`.
- `src/wp-includes/style-engine/class-wp-style-engine-css-declarations.php`
  - `filter_declaration()` (line ~190) calls `safecss_filter_attr( "{$property}:{$spacer}{$filtered_value}" )`
    and emits the returned declaration into a `selector{ ... }` rule.
- Allowed state‑capable blocks: `WP_Theme_JSON::VALID_BLOCK_PSEUDO_SELECTORS`
  (`src/wp-includes/class-wp-theme-json.php` line ~664) = `core/button`, `core/navigation-link`.

### Attacker‑controlled input → sink trace
1. Attacker (role **Author**, `edit_posts`+`publish_posts`, **no `unfiltered_html`**) submits
   `post_content` (via wp‑admin or `POST /wp/v2/posts`) containing a `core/button` block whose
   block‑delimiter JSON sets a hover style value:
   `{"style":{":hover":{"color":{"text":"rotate(0}.evil-injected{background:url(https://attacker.example/x.png)})"}}}}`
2. Save pipeline: `content_save_pre` → `wp_filter_post_kses()` (post context, because the
   user lacks `unfiltered_html`). kses sanitizes **HTML tags/attributes only**; the block
   `style` value lives inside an HTML *comment* delimiter, so it is **not** touched. Payload
   is stored intact. (Verified.)
3. Front‑end render: `do_blocks()` → `render_block` → `wp_render_block_states_support()` →
   style engine → `filter_declaration()` → `safecss_filter_attr()`. The `}` is inside
   `rotate(...)`, so it is removed from `$css_test_string`, the check passes, and the
   original value (with `}`) is written into the generated CSS rule.

### Expected vs. actual behavior
- **Expected:** a non‑`unfiltered_html` user cannot cause raw, attacker‑chosen CSS rules to
  appear in rendered output; `safecss_filter_attr()` neutralizes rule‑breaking characters.
- **Actual:** the emitted front‑end stylesheet is
  `.wp-states-XXXXXXXX .wp-block-button__link:hover{color:rotate(0}.evil-injected{background:url(https://attacker.example/x.png)}) !important;}`
  which browsers (CSS Syntax L3 error recovery) parse as the intended rule (dropped, invalid)
  **plus** a new valid global rule `.evil-injected{background:url(https://attacker.example/x.png)}`.

---

### Local reproduction (repository test environment)

Environment: repo `src/` bootstrapped against a local MariaDB install (`wp_install()`),
PHP 8.4. Scripts run against the real `wp-settings.php` bootstrap.

**(a) Root‑cause unit check — `}` survives inside allowed functions**
```
IN : transform: rotate(30deg})        OUT: transform: rotate(30deg})      <-- CONTAINS }
IN : width: calc(10px})               OUT: width: calc(10px})             <-- CONTAINS }
IN : color: var(--x})                 OUT: color: var(--x})               <-- CONTAINS }
IN : background: linear-gradient(red}, blue)  OUT: background: linear-gradient(red}, blue)  <-- CONTAINS }
IN : color: red}                      OUT:                                (correctly stripped — bare } outside a function)
```

**(b) Style‑engine stylesheet emission (states path building block)**
```php
WP_Style_Engine_CSS_Declarations::add_declaration('transform','rotate(30deg})',['important'=>true]);
// get_declarations_string() => "transform:rotate(30deg}) !important;"
wp_style_engine_get_stylesheet_from_css_rules([
  ['selector'=>'.victim','declarations'=>['transform'=>'rotate(30deg})']]
]);
// => ".victim{transform:rotate(30deg});}"   (the } is inside the rule body)
```

**(c) Full Author → insert → render chain (definitive)**
```
current user roles: author
has unfiltered_html: no
has publish_posts: YES
insert result: post 4 created
stored contains payload: YES
EMITTED FRONT-END STYLESHEET:
.wp-states-0da985f7 .wp-block-button__link:hover{color:rotate(0}.evil-injected{background:url(https://attacker.example/x.png)}) !important;}
ARBITRARY RULE INJECTED (.evil-injected): YES — vulnerable
```
The payload survived `wp_filter_post_kses()` on save and produced an attacker‑controlled CSS
rule (with an outbound `url()`) in the front‑end block‑supports stylesheet.

### Duplicate / history check
- Existing kses tests (`tests/phpunit/tests/kses.php`) explicitly assert that content inside
  allowed functions is **preserved** — e.g. line ~1429:
  `'background-image: linear-gradient(red, expression(alert))'` is expected to pass through
  unchanged. This documents the *inline‑style* contract of `safecss_filter_attr()` (where a
  `}` is inert). No test asserts that `}` is removed inside functions, and none covers the
  *stylesheet* use of the sanitizer's output.
- The exploitable sink (`block-supports/states.php`, using `safecss_filter_attr()` output in
  a real CSS rule block reachable with arbitrary `style` values) is new in 7.1.0. No matching
  advisory/test found in the repository.

---

## Supported‑version validation (added after version testing)

Testing method: the official `WordPress/wordpress-develop` release tags `7.1.2`,
`7.1.0`, `7.0.6`, `7.0.3`, `7.0.2` were fetched and the source trees bootstrapped against
local MariaDB databases. The **same attack model** was run against each runnable release:
Author account (no `unfiltered_html`, has `publish_posts`) → `wp_insert_post()` of a
`core/button` block with a crafted `:hover` `color.text` value → `do_blocks()` render →
inspect the block‑supports stylesheet.

### SUPPORTED VERSION STATUS
- **7.1.2 (latest supported): AFFECTED** — verified end‑to‑end.
- **7.0.6 (latest 7.0.x): NOT AFFECTED** — the sink does not exist in 7.0.x.
- **7.2‑alpha (63166): AFFECTED** — original finding.

### 7.1.2 verified run
```
VER=7.1.2-src roles=author unfiltered_html=no publish_posts=YES
insert=post 4  kses_survives=YES
STYLESHEET: .wp-states-0da985f7 .wp-block-button__link:hover{color:rotate(0}.evil-injected{background:url(https://attacker.example/x.png)}) !important;}
EXTERNAL_URL_RULE_INJECTED=YES
```
All chain conditions hold on 7.1.2: payload survives save‑time KSES, reaches the stylesheet
generator, breaks out of the CSS declaration/rule, and produces an attacker‑controlled rule
containing an external `url()`.

### 7.0.6 verified run
```
VER=7.0.6-src roles=author unfiltered_html=no publish_posts=YES
insert=post 4  kses_survives=YES
STYLESHEET:
EXTERNAL_URL_RULE_INJECTED=no
```
On 7.0.x the payload still survives KSES, but `src/wp-includes/block-supports/states.php`
does not exist and no `wp_render_block_states_support()` filter runs, so no stylesheet is
generated from block `style` values and there is no Author‑reachable stylesheet sink. The
latent `safecss_filter_attr()` brace behaviour is present in 7.0.x but is not reachable by a
low‑privilege user via this path.

### INTRODUCTION POINT
The exploitable sink — the **block "state styles" feature**
(`src/wp-includes/block-supports/states.php`, `wp_render_block_states_support()` on
`render_block`, feeding arbitrary block `style` values through the style engine into a
generated stylesheet) — first shipped in the **WordPress 7.1.0 release**
(present in tags `7.1.0`/`7.1.1`/`7.1.2`; absent in `7.0.6`). Public feature write‑up:
"Pseudo and custom style states in WordPress 7.1"
(make.wordpress.org/core/2026/08/05/…). The underlying `safecss_filter_attr()` behaviour of
excluding balanced allowed‑function contents from the final safety check predates this and
is old code; it becomes a security defect only once its output is placed into a stylesheet
rule, which the 7.1.0 states feature is the first low‑privilege‑reachable path to do.
`src/wp-includes/block-supports/states.php` and
`WP_Style_Engine_CSS_Declarations::filter_declaration()` are byte‑identical between 7.1.2 and
7.2‑alpha on the exploit path (the only `states.php` delta is a trivial `isset()` guard on
line 402); the `safecss_filter_attr()` function‑strip/check block is identical across 7.1.2
and 7.2‑alpha.

### FIX STATUS
**UNFIXED** as of the latest supported release **7.1.2** and in **7.2‑alpha**. Not addressed
by any shipped security release:
- **7.0.3** (Anthropic‑credited safecss fix) is a *different root cause* — a *fail‑open* when
  the recursive function‑stripping `preg_replace()` hits a PCRE backtrack/stack limit.
  Primary‑source diff `7.0.2 → 7.0.3` of `safecss_filter_attr()`:
  ```
  + // Bail if the recursive function stripping hit a PCRE error (e.g. stack/backtrack limit).
  + if ( null === $css_test_string ) {
  +     continue;
  + }
  - $allow_css = ! preg_match( '%[\\\(&=}]|/\*%', $css_test_string );
  + $allow_css = 0 === preg_match( '%[\\\(&=}]|/\*%', $css_test_string );
  ```
  This finding does **not** rely on a PCRE failure; the function‑stripping succeeds and
  legitimately removes a balanced `func(...)` group that carries the `}`. The bypass
  reproduces on 7.1.2, which already contains the 7.0.3 fix.
- **7.1.1** security fixes are all unrelated (XML‑RPC `edit_css` capability bypass;
  custom‑header stored XSS; `wpautop()` unauth stored XSS; contributor arbitrary post
  overwrite; REST templates path traversal; anonymous comment XSS).

### DUPLICATE / KNOWN STATUS
**Not a known duplicate.** No Trac ticket, CVE, WPScan/Patchstack advisory, or security‑release
entry was found describing this root cause + exploit path (a `}` surviving inside an allowed
CSS function in `safecss_filter_attr()` and breaking out of a **generated stylesheet rule**
via the block state‑styles sink). The only adjacent public item is the 7.0.3 safecss
fail‑open fix, shown above to be a materially different root cause. Blog/advisory pages
(patchstack, wpscan, wordpress.org, wordify, therepository) were egress‑blocked from this
environment; the distinguishing evidence used here is primary‑source (release‑tag code and
diffs) plus search result summaries, which is stronger for the duplicate determination.

### Root‑cause / fix direction (not applied)
The mismatch is that `safecss_filter_attr()` validates a function‑stripped copy but emits the
original. Options: (a) reject/neutralize declaration *values* containing `}` (and other
rule‑structural characters) before they are placed into a stylesheet rule in
`WP_Style_Engine_CSS_Declarations::filter_declaration()`; and/or (b) have
`safecss_filter_attr()` also reject values whose original form contains `}` even inside
functions when destined for stylesheet output. `}` legitimately never appears in a valid CSS
property value.

---

## IMPACT VALIDATION (runtime, WordPress 7.1.2) — CONCLUSION: NOT EXPLOITABLE

Method: real 7.1.2 release tree served over HTTP (`php -S`), MariaDB backend, the malicious
`core/button` post created by an **Author** (no `unfiltered_html`). The rendered front-end page
was loaded in headless **Chromium (Playwright 1.56.1, build 1194)**, with an attacker-controlled
HTTP logging server on `127.0.0.1:9099` as the `url()` target.

### The generated stylesheet text does contain the smuggled `}` …
Served page, `core-block-supports` inline stylesheet:
```
.wp-states-da56f435 .wp-block-button__link:hover {
	color: rotate(0}.wp-block-button__link{background-image:url(http://127.0.0.1:9099/btn-fired)!important}) !important;
}
```

### … but the browser does NOT break out of the rule.
Chromium CSSOM after loading the page:
```
states rule: ".wp-states-da56f435 .wp-block-button__link:hover { }"   (EMPTY — invalid decl dropped)
hasBody=false  hasBtnRule=false  hasEvil=false   totalRulesParsed=194
computed .wp-block-button__link background-image: none
Attacker requests observed: []   (zero)
```
Reason: `safecss_filter_attr()` only permits a `}` to survive when it is **inside** a CSS
function's `(...)` (it is removed from the safety-check test string as part of a
`rotate()/calc()/var()/url()/gradient()` block). Per the CSS Syntax Level 3 spec, a `}` inside a
`(...)` block is consumed as part of the declaration value and does **not** end the qualified
rule. The whole payload is therefore parsed as the (invalid) value of `color`, the declaration is
discarded, the `:hover` rule is left empty, and **no new rule is created**. No `url()` is fetched.

### Positive control (proves the test harness detects real breakouts)
A page whose inline CSS contains a genuine **bare** `}` breakout
(`.pc .btn:hover{color:red}.evil-injected{background-image:url(.../POSITIVE-CONTROL)!important}`)
was loaded in the same harness:
```
Attacker requests observed: ["http://127.0.0.1:9099/POSITIVE-CONTROL"]   (FIRED)
```
So the negative result above is real, not a harness artifact.

### safecss cannot emit a rule-terminating `}` in the first place
Battery against 7.1.2's `safecss_filter_attr()` — for each output, whether it contains a `}`
outside any `(...)` (i.e. capable of ending a rule):
```
bare brace              -> (empty)                                  bare-} outside (): no
bare brace + rule       -> (empty)                                  bare-} outside (): no
brace via calc paren    -> width: calc(1px}.evil{x:y})              bare-} outside (): no
brace via rotate        -> transform: rotate(0}.evil{x:y})          bare-} outside (): no
brace via url           -> (empty)                                  bare-} outside (): no
brace via gradient      -> background: linear-gradient(red}.evil{x:y, blue)  bare-} outside (): no
escaped brace (\7d)     -> (empty)                                  bare-} outside (): no
close-paren then brace  -> (empty)                                  bare-} outside (): no
```
Every `}` that survives is trapped inside `(...)`; any `}` at rule-nesting level is stripped.
A CSS rule can only be closed by a `}` outside `()`, so no breakout is achievable.

### Structured result
- **CONFIRMED IMPACT:** none. No attacker-controlled CSS rule is created; no outbound request; no computed-style effect.
- **ATTACKER PRIVILEGE:** Author (`edit_posts`/`publish_posts`, no `unfiltered_html`) — moot, as there is no effect.
- **VICTIM REQUIREMENT:** would have to view the post's front end; irrelevant since nothing fires.
- **EXFILTRATION:** NO — attacker log empty in every viewer context; no `url()` fetch possible (no rule can be injected).
- **PRIVILEGE / SECURITY-BOUNDARY CROSSING:** NO — the safecss boundary is not bypassed in effect; every surviving `}` is inert. The only author-reachable behavior (a legitimate `:hover` background `url()` via the state-styles feature itself) is by design and equivalent to embedding a remote image in a post.
- **IMPACT LIMITATIONS:** cannot produce a rule-terminating `}`; cannot inject a selector/rule; cannot trigger a conditional `url()`; cannot exfiltrate; no admin/front-end privileged impact; no CSSOM corruption of adjacent rules (194 rules parsed intact).
- **SEVERITY EVIDENCE:** empty `:hover` rule in CSSOM; zero attacker requests; positive control fired; safecss battery shows no bare `}` is ever emitted.

### Bottom line
The original finding correctly identified a cosmetic imperfection in `safecss_filter_attr()`
(it can emit a `}` inside a function), but that imperfection has **no security impact**: the
`}` is always paren-enclosed and inert under real CSS parsing, so the "stored CSS injection /
stylesheet breakout" is not exploitable. The finding should not be reported as a vulnerability.
