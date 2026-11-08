export type RGB = [number, number, number];
export interface FieldPalette { bg: RGB; ash: RGB; ember: RGB }
export interface FieldData { coordinates: ArrayLike<number>; flags: ArrayLike<number> }

/** One aspect-preserving projection for the poster and the live field. */
export function fieldPoint(x: number, y: number, width: number, height: number, phone = width / height < 1) {
  const baseWidth = phone ? 390 : 1440, baseHeight = phone ? 784 : 824;
  const cover = Math.max(width / baseWidth, height / baseHeight);
  const angle = phone ? -0.30 : -0.45;
  const scale = (phone ? baseWidth / 27000 : baseHeight / 34000) * cover;
  const cx = baseWidth * (phone ? 0.60 : 0.76) * cover + (width - baseWidth * cover) / 2;
  const cy = baseHeight * (phone ? 0.27 : 0.47) * cover + (height - baseHeight * cover) / 2;
  const dx = x - 35000, dy = y - 35000;
  return [cx + (dx * Math.cos(angle) - dy * Math.sin(angle)) * scale,
    cy + (dx * Math.sin(angle) + dy * Math.cos(angle)) * scale];
}

/** Deterministic rasterisation. Every row is drawn, including duplicate vectors. */
export function renderField(data: FieldData, width: number, height: number, palette: FieldPalette, density = 1) {
  const phone = width / density <= 700;
  const pointScale = Math.max(width / (phone ? 390 : 1440), height / (phone ? 784 : 824));
  const pixels = new Uint8ClampedArray(width * height * 4);
  for (let i = 0; i < pixels.length; i += 4) {
    pixels[i] = palette.bg[0]; pixels[i + 1] = palette.bg[1]; pixels[i + 2] = palette.bg[2]; pixels[i + 3] = 255;
  }
  const circle = (x: number, y: number, radius: number, color: RGB, alpha: number, glow = false) => {
    const x0 = Math.max(0, Math.floor(x - radius - 1)), x1 = Math.min(width - 1, Math.ceil(x + radius + 1));
    const y0 = Math.max(0, Math.floor(y - radius - 1)), y1 = Math.min(height - 1, Math.ceil(y + radius + 1));
    for (let py = y0; py <= y1; py++) for (let px = x0; px <= x1; px++) {
      const d = Math.hypot(px + 0.5 - x, py + 0.5 - y);
      const a = alpha * (glow ? Math.max(0, 1 - d / radius) ** 2 : Math.max(0, Math.min(1, radius + 0.5 - d)));
      if (!a) continue;
      const i = (py * width + px) * 4;
      for (let c = 0; c < 3; c++) pixels[i + c] += (color[c] - pixels[i + c]) * a;
    }
  };
  for (const hot of [false, true]) for (let i = 0; i < data.flags.length; i++) {
    if (Boolean(data.flags[i] & 6) !== hot) continue;
    const [x, y] = fieldPoint(data.coordinates[i * 2], data.coordinates[i * 2 + 1], width, height, phone);
    if (hot) {
      circle(x, y, 7 * pointScale, palette.ember, 0.22, true);
      circle(x, y, (data.flags[i] & 4 ? 1.4 : 1.05) * pointScale, palette.ember, data.flags[i] & 4 ? 1 : 0.85);
    } else circle(x, y, 0.58 * pointScale, palette.ash, 0.28);
  }
  return pixels;
}
