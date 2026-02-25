# hackfate.us Prismatic Nav Hover Effect — Design Document

**Date**: 2026-02-24
**Status**: Approved
**Author**: Acid + Claude

---

## Objective

Add a prismatic gradient sweep hover effect to 4 major navigation links on hackfate.us, adapted from the Obsidian Refraction design. The effect signals that these are the site's primary technical showcase pages without overwhelming the nav with excessive animation.

## Effect Description

On hover, the link text fills with a left-to-right gradient sweep using the site's existing color palette (cyan, magenta, purple). The sweep takes 0.5s and reverses on mouse-out. Non-prismatic links retain their current simple cyan hover.

## Target Links (4 of 11)

| Link | Page | Rationale |
|------|------|-----------|
| Technology | technology.html | NINE65 stack overview |
| Three-Lock | three-lock.html | Flagship security architecture |
| Benchmarks | benchmarks.html | Performance evidence |
| Proofs | proofs.html | Formal verification showcase |

## Approach

**CSS `background-clip: text` gradient sweep** — a `linear-gradient` wider than the text (200% width), positioned off-screen by default. On hover, `background-position` shifts to sweep the gradient through the text.

### Why This Approach

- Pure CSS, zero JavaScript
- GPU-accelerated (only `background-position` animates)
- No layout shifts, no reflows
- ~20 lines of CSS added
- Works with existing `transition` already on nav links
- Gracefully degrades (older browsers see plain text)

### Rejected Alternatives

- **`::before` overlay sweep**: Requires `position: relative` + `overflow: hidden`, conflicts with tight nav spacing
- **Text gradient + underline combo**: Too much animation, borders on chaos

## Implementation

### CSS (styles.css)

```css
/* Right half = solid gray (visible at rest), left half = prismatic (revealed on hover) */
.nav-links a.nav-prismatic {
    background: linear-gradient(
        90deg,
        var(--accent-cyan) 0%,
        var(--accent-magenta) 20%,
        var(--accent-purple) 40%,
        var(--accent-cyan) 50%,
        var(--text-secondary) 50.1%,
        var(--text-secondary) 100%
    );
    background-size: 200% 100%;
    background-position: 100% 0;
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
    transition: background-position 0.5s ease;
}

.nav-links a.nav-prismatic:hover {
    background-position: 0% 0;
}
```

### HTML (19 files)

Add `class="nav-prismatic"` to 4 links in every page's `<nav>`:

```html
<a href="technology.html" class="nav-prismatic">Technology</a>
<a href="three-lock.html" class="nav-prismatic">Three-Lock</a>
<a href="benchmarks.html" class="nav-prismatic">Benchmarks</a>
<a href="proofs.html" class="nav-prismatic">Proofs</a>
```

### Files Changed

- `styles.css` — add prismatic class (~20 lines)
- 19 HTML files — add `nav-prismatic` class to 4 links each

### No Changes To

- `script.js` — no JavaScript needed
- No new files or dependencies
- Mobile nav behavior unchanged

## Accessibility

- Gradient is decorative only; link text remains readable
- `prefers-reduced-motion` media query will disable the animation
- Focus-visible styles unchanged (cyan outline)

## Risk

- Minimal — CSS-only change, class-based opt-in
- Worst case on unsupported browser: links display as plain text (existing fallback)
