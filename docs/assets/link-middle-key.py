import sys, numpy as np, cv2
from PIL import Image
src, out = sys.argv[1], sys.argv[2]
ang = float(sys.argv[3]) if len(sys.argv) > 3 else 38     # where the link meets the big ring (degrees below horizontal, right side)
S = 4
a = np.asarray(Image.open(src).convert('RGB').resize((240*S, 240*S), Image.LANCZOS)).astype(np.float64)
H, W, _ = a.shape
yy, xx = np.mgrid[0:H, 0:W].astype(np.float64)
P = lambda v: (v + 0.5) * S
u8 = lambda x: np.clip(x, 0, 255).astype(np.uint8)
bc = np.array([P(119), P(116.5)]); br = 15.8*S
hc = np.array([P(118.5), P(113.3)]); hr = 5.0*S
rc = np.array([484.0, 364.0]); r_in, r_out = 76.0, 104.0
rr = np.hypot(xx-rc[0], yy-rc[1])
bow = (xx-bc[0])**2 + (yy-bc[1])**2 <= br**2
hole = (xx-hc[0])**2 + (yy-hc[1])**2 <= hr**2

# 1. remove the old stick: on the bow face, in the hole, and between the rim and the ring
stick = (np.array([[115, 113], [120, 106], [127, 98.5], [134, 101.5], [127, 111], [121, 118]]) + 0.5) * S
m = np.zeros((H, W), np.uint8); cv2.fillPoly(m, [stick.astype(np.int32)], 1)
face = (m.astype(bool) & bow & ~hole)
img = cv2.inpaint(u8(a), face.astype(np.uint8), 7, cv2.INPAINT_TELEA).astype(np.float64)
# the hole: dark, like the shield behind it
dark = a[int(rc[1]), int(rc[0])] * 0.75
hw = cv2.GaussianBlur(((xx-hc[0])**2 + (yy-hc[1])**2 <= (hr-1.2*S)**2).astype(np.float32), (0, 0), 1.2)[..., None]
img = img*(1-hw) + dark*hw

prof = a[int(rc[1])-2:int(rc[1])+3, int(rc[0]-r_out):int(rc[0]-r_in)+1].mean(0)
def ring_colour(r, shade=1.0):
    t = np.clip((r_out - r) / (r_out - r_in), 0, 1) * (len(prof)-1)
    i = np.floor(t).astype(int); f = (t - i)[..., None]; j = np.minimum(i+1, len(prof)-1)
    return (prof[i]*(1-f) + prof[j]*f) * shade

# 2. the link: a ring from the key's hole to the big ring
th = np.radians(ang)
rmid = (r_in + r_out) / 2
R = rc + rmid*np.array([np.cos(th), np.sin(th)])        # on the big ring's band
Hh = hc + np.array([0.0, hr*0.15])                       # in the key's hole
c = (R + Hh) / 2
v = R - Hh; length = np.hypot(*v); ux = v/length; uy = np.array([-ux[1], ux[0]])
semi_a = length/2 + 5.5*S; semi_b = 4.6*S; thick = 3.3*S
X = (xx-c[0])*ux[0] + (yy-c[1])*ux[1]
Y = (xx-c[0])*uy[0] + (yy-c[1])*uy[1]
e = np.hypot(X/semi_a, Y/semi_b)
g = np.hypot(X/semi_a**2, Y/semi_b**2) + 1e-9
dist = (e-1)/g*e
al = np.clip(thick/2 + 0.7 - np.abs(dist), 0, 1)
t = np.clip((thick/2 - dist)/thick, 0, 1)
lcol = ring_colour(r_out - t*(r_out-r_in), 1.08)
side = Y        # which side of the link's long axis

def over(img, col, al): al = al[..., None]; return img*(1-al) + col*al
# the link passes through the hole: one side of it behind the key (seen only in the hole),
# the other side in front of the key's face. At the top it goes round the big ring:
# in front of the band on one side, behind it on the other.
behind_key = bow & ~hole & (side > 0) & ((xx-bc[0])**2 + (yy-bc[1])**2 <= (br-0.5*S)**2)
img = over(img, lcol, al * ~behind_key)
ring_in_front = (side < 0) & (rr >= r_in) & (rr <= r_out) & ~bow
rw = cv2.GaussianBlur(ring_in_front.astype(np.float32), (0, 0), 0.7) * al
img = over(img, a, rw)              # the original ring pixels back on top there
Image.fromarray(u8(img)).save(out)
