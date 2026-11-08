/** Resolve the shared palette once when a canvas renderer starts. */
export function readCanvasTheme() {
  const style = getComputedStyle(document.documentElement);
  const token = (name: string) => style.getPropertyValue(`--${name}`).trim();
  return {
    bg: token("bg"), panel: token("panel"), line: token("line"),
    text: token("text"), muted: token("muted"),
    known: token("known"), knownDim: token("known-dim"),
    fieldAsh: token("field-ash"),
    accent: token("accent"), strong: token("accent-strong"),
    glow: token("accent-glow"), halo: token("accent-halo"),
    clear: token("clear"), labelSize: token("type-label"),
  };
}
