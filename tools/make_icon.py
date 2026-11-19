"""Generate raven.ico — a cyan→magenta shield with a check, on deep navy."""
from pathlib import Path

from PIL import Image, ImageDraw

S = 256
BG = (4, 5, 12, 255)
CYAN = (5, 217, 232)
MAGENTA = (255, 42, 109)

# Diagonal cyan -> magenta gradient
grad = Image.new("RGB", (S, S))
gpx = grad.load()
for y in range(S):
    for x in range(S):
        t = (x + y) / (2 * S)
        gpx[x, y] = tuple(round(CYAN[i] + (MAGENTA[i] - CYAN[i]) * t) for i in range(3))

# Shield silhouette as a mask
mask = Image.new("L", (S, S), 0)
md = ImageDraw.Draw(mask)
cx, top, w, bot = S / 2, 36, 150, 226
md.polygon([(cx, top), (cx + w / 2, top + 26), (cx + w / 2, 140),
            (cx, bot), (cx - w / 2, 140), (cx - w / 2, top + 26)], fill=255)

# Compose: rounded dark background + gradient shield + dark check
img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
d = ImageDraw.Draw(img)
d.rounded_rectangle([8, 8, S - 8, S - 8], radius=46, fill=BG)
img.paste(grad, (0, 0), mask)
d.line([(cx - 34, 132), (cx - 6, 160), (cx + 40, 104)], fill=BG, width=16, joint="curve")

sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
out = Path(__file__).resolve().parent.parent / "raven.ico"
img.save(out, format="ICO", sizes=sizes)
print("wrote", out)
