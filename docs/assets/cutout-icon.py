# Cut Rik's icon out of its painted checkerboard: flood-fill the light, grey
# (unsaturated) squares from the border, then estimate alpha in the border band
# by unmixing each edge pixel between the nearby background and shield colours.
import sys
import numpy as np
from PIL import Image
from collections import deque
src, out = sys.argv[1], sys.argv[2]
im = np.asarray(Image.open(src).convert('RGB')).astype(np.float64)
h, w, _ = im.shape
sat = im.max(2) - im.min(2)
val = im.min(2)
bglike = (sat < 14) & (val > 196)
bg = np.zeros((h, w), bool)
q = deque((y, x) for y in range(h) for x in (0, w-1)) + deque((y, x) for x in range(w) for y in (0, h-1))
for y, x in q: pass
q = deque([(y, x) for y in range(h) for x in (0, w-1)] + [(y, x) for x in range(w) for y in (0, h-1)])
while q:
    y, x = q.popleft()
    if bg[y, x] or not bglike[y, x]: continue
    bg[y, x] = True
    for dy in (-1, 0, 1):
        for dx in (-1, 0, 1):
            ny, nx = y+dy, x+dx
            if 0 <= ny < h and 0 <= nx < w and not bg[ny, nx]: q.append((ny, nx))
alpha = np.where(bg, 0.0, 1.0)
rgb = im.copy()
# distance (in pixels, up to 3) of every pixel from the background
from scipy import ndimage
dist = ndimage.distance_transform_edt(~bg)
band = (~bg) & (dist <= 2.5)
inner = (~bg) & (dist > 3.5)
R = 4
for y, x in zip(*np.nonzero(band)):
    y0, y1, x0, x1 = max(0, y-R), min(h, y+R+1), max(0, x-R), min(w, x+R+1)
    b = bg[y0:y1, x0:x1]; f = inner[y0:y1, x0:x1]
    if not b.any() or not f.any(): continue
    B = im[y0:y1, x0:x1][b].mean(0)
    F = im[y0:y1, x0:x1][f].mean(0)
    C = im[y, x]
    d = F - B
    a = float(np.clip(np.dot(C - B, d) / max(np.dot(d, d), 1e-6), 0, 1))
    alpha[y, x] = a
    if a > 0.02:
        rgb[y, x] = np.clip((C - (1 - a) * B) / a, 0, 255)   # remove the grey that was mixed in
out_im = np.dstack([rgb, alpha * 255]).round().astype(np.uint8)
img = Image.fromarray(out_im, 'RGBA')
bbox = img.getbbox()
img = img.crop(bbox)
img.save(out)
print('bbox', bbox, 'size', img.size)
