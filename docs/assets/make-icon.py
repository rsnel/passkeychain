# PassKeyChain icon: a blue shield with a crown, three keys on a ring.
# One description -> SVG (preview, website logo) and Android VectorDrawables.
import sys, math, re
out = sys.argv[1]

# ---- shapes, in a 108x108 viewport (adaptive icon; safe zone is the central 66) ----
SHIELD = "M54,25 C63,29.5 72,30.5 80,29.5 L80,53 C80,72 68.5,85 54,92 C39.5,85 28,72 28,53 L28,29.5 C36,30.5 45,29.5 54,25 Z"
LEFT_HALF = "M54,25 C45,29.5 36,30.5 28,29.5 L28,53 C28,72 39.5,85 54,92 Z"

def scaled(d, k, cx, cy):
    """scale an absolute-coordinates path about (cx, cy)"""
    def num(m):
        x, y = float(m.group(1)), float(m.group(2))
        return f"{cx + (x - cx) * k:.2f},{cy + (y - cy) * k:.2f}"
    return re.sub(r"(-?\d+\.?\d*),(-?\d+\.?\d*)", num, d)

INNER = scaled(SHIELD, 0.84, 54, 57)          # a wide bright rim around a darker face
SHINE = scaled(LEFT_HALF, 0.84, 54, 57)       # left half of the face, a lighter bevel
CROWN  = "M41,27.5 L39.2,14.5 L47.2,20.8 L54,10.5 L60.8,20.8 L68.8,14.5 L67,27.5 C61,25.6 47,25.6 41,27.5 Z"
RING_C, RING_R = (54.0, 41.0), 7.6

def ring_path(cx, cy, r):
    return f"M{cx-r},{cy} a{r},{r} 0 1,0 {2*r},0 a{r},{r} 0 1,0 {-2*r},0"

def key_path():
    """a key pointing down, its bow centred on (0,0); hole as an even-odd subpath"""
    bow = "M-5.6,0 a5.6,5.6 0 1,0 11.2,0 a5.6,5.6 0 1,0 -11.2,0 Z"
    hole = "M-2.1,-0.6 a2.1,2.1 0 1,1 4.2,0 a2.1,2.1 0 1,1 -4.2,0 Z"
    shaft = "M-2.1,4.4 L2.1,4.4 L2.1,23.6 C2.1,25.4 -2.1,25.4 -2.1,23.6 Z"
    teeth = "M1.9,14.8 L5.6,14.8 L5.6,17.8 L1.9,17.8 Z M1.9,19.6 L4.6,19.6 L4.6,22.4 L1.9,22.4 Z"
    return bow + " " + hole + " " + shaft + " " + teeth

# gradients: (x1,y1,x2,y2, [(offset, color)])
G = {
    "bg":     ("radial", 54, 46, 70, [(0, "#123C8F"), (1, "#060F33")]),
    "crown":  ("linear", 40, 11, 68, 28, [(0, "#7DE3FF"), (1, "#2563EB")]),
    "rim":    ("linear", 30, 26, 78, 92, [(0, "#7BE4FF"), (0.45, "#2F86F6"), (1, "#6A2BD9")]),
    "inner":  ("linear", 34, 31, 74, 87, [(0, "#1F4FCF"), (1, "#14106A")]),
    "key":    ("linear", 0, -6, 0, 26, [(0, "#C4F3FF"), (1, "#4C9DFF")]),
    "keyb":   ("linear", 0, -6, 0, 26, [(0, "#8FDCFF"), (1, "#3577E8")]),
}

KEYS = [  # (translate x, y, rotation, scale, gradient): bows on the ring, blades down
    (49.5, 49.0, 27, 1.08, "keyb"),
    (58.5, 49.0, -27, 1.08, "keyb"),
    (54.0, 49.5, 0, 1.3, "key"),
]
# everything is drawn at this scale around the middle, so that crown and point
# stay inside the adaptive icon's safe zone (the central 66 of 108)
FIT = "translate(54 54) scale(0.8) translate(-54 -51.25)"

# ---- SVG ----
def svg_grad(gid, spec, units_user=True):
    if spec[0] == "radial":
        _, cx, cy, r, stops = spec
        st = "".join(f"<stop offset='{o}' stop-color='{c}'/>" for o, c in stops)
        return f"<radialGradient id='{gid}' gradientUnits='userSpaceOnUse' cx='{cx}' cy='{cy}' r='{r}'>{st}</radialGradient>"
    _, x1, y1, x2, y2, stops = spec
    st = "".join(f"<stop offset='{o}' stop-color='{c}'/>" for o, c in stops)
    return f"<linearGradient id='{gid}' gradientUnits='userSpaceOnUse' x1='{x1}' y1='{y1}' x2='{x2}' y2='{y2}'>{st}</linearGradient>"

def svg_foreground():
    p = []
    p.append(f"<path d='{CROWN}' fill='url(#crown)'/>")
    p.append(f"<path d='{SHIELD}' fill='url(#rim)'/>")
    p.append(f"<path d='{INNER}' fill='url(#inner)' stroke='#0B1250' stroke-opacity='.6' stroke-width='1.2'/>")
    p.append(f"<path d='{SHINE}' fill='#FFFFFF' fill-opacity='0.08'/>")
    cx, cy = RING_C
    p.append(f"<path d='{ring_path(cx, cy, RING_R)}' fill='none' stroke='#0E1A66' stroke-opacity='.55' stroke-width='4.2'/>")
    p.append(f"<path d='{ring_path(cx, cy, RING_R)}' fill='none' stroke='#9BE7FF' stroke-width='2.6'/>")
    for tx, ty, rot, sc, g in KEYS:
        p.append(f"<g transform='translate({tx} {ty}) rotate({rot}) scale({sc})'>"
                 f"<path d='{key_path()}' fill='#0E1A66' fill-opacity='.45' fill-rule='evenodd' transform='translate(0.9 1.2)'/>"
                 f"<path d='{key_path()}' fill='url(#{g})' fill-rule='evenodd'/></g>")
    return "".join(p)

def svg_doc(kind):
    defs = "".join(svg_grad(k, v) for k, v in G.items())
    # keys use gradients in their own (rotated) space: objectBoundingBox-free user space works per group
    fg = svg_foreground()
    if kind == "square":     # website logo: rounded square, filled more than a launcher icon
        return (f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 108 108'><defs>{defs}</defs>"
                f"<rect width='108' height='108' rx='24' fill='url(#bg)'/>"
                f"<g transform='translate(54 54) scale(1.12) translate(-54 -51.25)'>{fg}</g></svg>")
    if kind == "launcher":   # what a launcher shows: the central 72 of the 108
        return (f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='18 18 72 72'><defs>{defs}</defs>"
                f"<rect width='108' height='108' fill='url(#bg)'/><g transform='{FIT}'>{fg}</g></svg>")

for k in ("square", "launcher"):
    open(f"{out}/icon_{k}.svg", "w").write(svg_doc(k))

# ---- Android VectorDrawable ----
A = "xmlns:android=\"http://schemas.android.com/apk/res/android\" xmlns:aapt=\"http://schemas.android.com/aapt\""
def vd_grad(spec):
    if spec[0] == "radial":
        _, cx, cy, r, stops = spec
        head = f"<gradient android:type=\"radial\" android:centerX=\"{cx}\" android:centerY=\"{cy}\" android:gradientRadius=\"{r}\">"
    else:
        _, x1, y1, x2, y2, stops = spec
        head = f"<gradient android:type=\"linear\" android:startX=\"{x1}\" android:startY=\"{y1}\" android:endX=\"{x2}\" android:endY=\"{y2}\">"
    items = "".join(f"<item android:offset=\"{o}\" android:color=\"{c}\"/>" for o, c in stops)
    return f"<aapt:attr name=\"android:fillColor\">{head}{items}</gradient></aapt:attr>"

def vd_path(d, grad=None, color=None, alpha=None, evenodd=False, stroke=None, sw=None, salpha=None):
    attrs = f"android:pathData=\"{d}\""
    if color: attrs += f" android:fillColor=\"{color}\""
    if alpha is not None: attrs += f" android:fillAlpha=\"{alpha}\""
    if evenodd: attrs += " android:fillType=\"evenOdd\""
    if stroke: attrs += f" android:strokeColor=\"{stroke}\" android:strokeWidth=\"{sw}\""
    if salpha is not None: attrs += f" android:strokeAlpha=\"{salpha}\""
    if grad: return f"<path {attrs}>{vd_grad(G[grad])}</path>"
    return f"<path {attrs}/>"

def vd_foreground_body():
    b = [vd_path(CROWN, "crown"), vd_path(SHIELD, "rim"), vd_path(INNER, "inner"),
         vd_path(INNER, stroke="#0B1250", sw=1.2, salpha=0.6), vd_path(SHINE, color="#FFFFFF", alpha=0.08)]
    cx, cy = RING_C
    b.append(vd_path(ring_path(cx, cy, RING_R), stroke="#0E1A66", sw=4.2, salpha=0.55))
    b.append(vd_path(ring_path(cx, cy, RING_R), stroke="#9BE7FF", sw=2.6))
    for tx, ty, rot, sc, g in KEYS:
        b.append(f"<group android:translateX=\"{tx}\" android:translateY=\"{ty}\" android:rotation=\"{rot}\" android:scaleX=\"{sc}\" android:scaleY=\"{sc}\">"
                 f"<group android:translateX=\"0.9\" android:translateY=\"1.2\">{vd_path(key_path(), color='#0E1A66', alpha=0.45, evenodd=True)}</group>"
                 f"{vd_path(key_path(), g, evenodd=True)}</group>")
    return "".join(b)

def vd(body, comment):
    return (f"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<!-- {comment} -->\n"
            f"<vector {A}\n    android:width=\"108dp\" android:height=\"108dp\"\n    android:viewportWidth=\"108\" android:viewportHeight=\"108\">\n"
            f"{body}\n</vector>\n")

FIT_VD = ("<group android:pivotX=\"54\" android:pivotY=\"51.25\" android:scaleX=\"0.8\" android:scaleY=\"0.8\" "
          "android:translateY=\"2.75\">{}</group>")
open(f"{out}/ic_launcher_foreground.xml", "w").write(vd(FIT_VD.format(vd_foreground_body()),
    "PassKeyChain launcher foreground: a blue shield with a crown, three keys on a ring. Generated with docs/assets/logo.svg."))
open(f"{out}/ic_launcher_background.xml", "w").write(vd(vd_path("M0,0h108v108h-108z", "bg"), "PassKeyChain launcher background: deep navy"))
# monochrome (themed icons): one colour, alpha only
mono = [vd_path(CROWN, color="#FF000000"),
        vd_path(SHIELD + " " + INNER, color="#FF000000", evenodd=True),   # the shield as an outline band
        vd_path(ring_path(*RING_C, RING_R), stroke="#FF000000", sw=2.6)]
for tx, ty, rot, sc, g in KEYS:
    mono.append(f"<group android:translateX=\"{tx}\" android:translateY=\"{ty}\" android:rotation=\"{rot}\" android:scaleX=\"{sc}\" android:scaleY=\"{sc}\">"
                f"{vd_path(key_path(), color='#FF000000', evenodd=True)}</group>")
open(f"{out}/ic_launcher_monochrome.xml", "w").write(vd(FIT_VD.format("".join(mono)), "PassKeyChain themed icon: shield outline, crown and keys in one colour"))
print("ok")
