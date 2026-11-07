# Builds the QR sign-in pictures of the website from qr-signin-source.svg:
#   qr-signin.svg                  the still picture (step colours), for "reduce motion"
#   qr-signin-animated.svg         the 8-step animation (SMIL, 18 s loop), caption below
#   qr-signin-animated-wide.svg    desktops: the steps listed beside the scene
#   qr-signin-animated-phone.svg   phones: larger labels, a big caption card, 4.5 s per step
# Run from the repository root:
#   python3 docs/assets/make-animation.py docs/assets/qr-signin-source.svg docs/assets/qr-signin.svg \
#     docs/assets/qr-signin-animated.svg docs/assets/qr-signin-animated-wide.svg docs/assets/qr-signin-animated-phone.svg
import re, sys
src_path, out_static, out_anim = sys.argv[1:4]
out_wide = sys.argv[4] if len(sys.argv) > 4 else None   # the desktop version, steps listed on the right
L = open(src_path).read().split('\n')
line = lambda n: L[n-1]              # 1-based, as in the file

FONT = "font-family=\"'Inter','Segoe UI',Roboto,Arial,sans-serif\""
STEP = {1:'#6C4CE0', 2:'#F2B705', 3:'#2F80ED', 4:'#12A4A0', 5:'#E8772E', 6:'#D6336C', 7:'#84B819', 8:'#1E9E5A'}
INK = lambda n: '#1B1B21' if n in (2, 7) else '#fff'

def recolour(s):
    # number badges: r=17 circle followed by its digit
    pat = re.compile(r"(<circle cx='[^']+' cy='[^']+' r='17' fill=')([^']+)(' stroke='#fff' stroke-width='3'/><text [^>]*fill=')([^']+)('>)(\d)(</text>)")
    return pat.sub(lambda m: m.group(1)+STEP[int(m.group(6))]+m.group(3)+INK(int(m.group(6)))+m.group(5)+m.group(6)+m.group(7), s)

# eight steps: "you approve" (the fingerprint) is step 7 now, the signature step 8
L[67] = L[67].replace(">6</text>", ">7</text>")   # line 68: badge on the fingerprint
L[65] = L[65].replace(">7</text>", ">8</text>")   # line 66: badge on the signature
L[69] = L[69].replace(">7</text>", ">8</text>")   # line 70: badge on "Signed in"
L = [recolour(x) for x in L]
open(out_static, 'w').write('\n'.join(L))

def set_timing(step):
    """[step] seconds per step; the last step is held 1.4 s longer, then the loop restarts"""
    global T, WIN, END
    WIN = {i: ((i-1)*step, i*step) for i in range(1, 9)}
    WIN[8] = (7*step, 8*step + 1.4)
    END = round(WIN[8][1] + .2, 3)
    T = round(END + .4, 3)

STEP_SECONDS = 2.0          # desktops and tablets: the steps are listed, or the caption is short
PHONE_STEP_SECONDS = 4.5    # phones: time to read the caption card
set_timing(STEP_SECONDS)
f = lambda t: f"{t/T:.4f}"

def appear(step):
    """fade in at the start of the step, stay until the loop ends"""
    s = WIN[step][0]
    if s == 0:
        return f"<animate attributeName='opacity' values='0;1;1;0' keyTimes='0;{f(.35)};{f(END)};1' dur='{T}s' repeatCount='indefinite'/>"
    return (f"<animate attributeName='opacity' values='0;0;1;1;0' keyTimes='0;{f(s)};{f(s+.35)};{f(END)};1' "
            f"dur='{T}s' repeatCount='indefinite'/>")

def only_during(step, fade=.15):
    s, e = WIN[step]
    a = [0, max(s, 1e-4), s+fade, e-fade, e, T] if s > 0 else [0, fade, e-fade, e, T]
    vals = '0;0;1;1;0;0' if s > 0 else '0;1;1;0;0'
    return f"<animate attributeName='opacity' values='{vals}' keyTimes='{';'.join(f(x) for x in a)}' dur='{T}s' repeatCount='indefinite'/>"

def wrap(step, body):
    return f"<g>{appear(step)}{body}</g>"

def token(step, path, glyph=None, travel=None, k=1.0):
    """a numbered disc in the step colour that travels [path] during the step"""
    s, e = WIN[step]
    if travel: s, e = travel
    t0, t1 = s + .25, e - .35
    kt = f"0;{f(t0)};{f(t1)};1"
    label = glyph or str(step)
    return (f"<g opacity='0'>{only_during(step)}"
            f"<g transform='scale({k})'><circle r='19' fill='{STEP[step]}' stroke='#fff' stroke-width='4'/>"
            f"<text y='7' text-anchor='middle' {FONT} font-size='19' font-weight='800' fill='{INK(step)}'>{label}</text></g>"
            f"<animateMotion path='{path}' keyPoints='0;0;1;1' keyTimes='{kt}' calcMode='linear' dur='{T}s' repeatCount='indefinite'/></g>")

def ripples(cx, cy, step, n=3, reach=150, start=10):
    s, e = WIN[step]
    out = []
    for k in range(n):
        a = s + .2 + k*.55; b = a + 1.0
        out.append(f"<circle cx='{cx}' cy='{cy}' r='{start}' fill='none' stroke='{STEP[step]}' stroke-width='5' opacity='0'>"
                   f"<animate attributeName='r' values='{start};{start};{reach};{reach}' keyTimes='0;{f(a)};{f(b)};1' dur='{T}s' repeatCount='indefinite'/>"
                   f"<animate attributeName='opacity' values='0;0;.85;0;0' keyTimes='0;{f(a)};{f(a+.05)};{f(b)};1' dur='{T}s' repeatCount='indefinite'/></circle>")
    return ''.join(out)

CAPTION = {1: 'The phone scans the QR code and derives keys',
           2: 'The phone connects to the tunnel server',
           3: 'Bluetooth: “I am nearby, meet me there”',
           4: 'The browser joins and starts the handshake',
           5: 'The phone answers: end-to-end encrypted now',
           6: 'The browser asks: “sign this?”',
           7: 'You approve: fingerprint, face or PIN',
           8: 'The phone sends the signature: signed in!'}

def captions():
    out = ["<rect x='70' y='712' width='860' height='64' rx='32' fill='#fff' stroke='#00000014'/>"]
    for i in range(1, 9):
        out.append(f"<g opacity='0'>{only_during(i)}"
                   f"<circle cx='112' cy='744' r='21' fill='{STEP[i]}'/>"
                   f"<text x='112' y='752' text-anchor='middle' {FONT} font-size='22' font-weight='800' fill='{INK(i)}'>{i}</text>"
                   f"<text x='150' y='753' {FONT} font-size='25' font-weight='700' fill='#1B1B21'>{CAPTION[i]}</text></g>")
    # progress: eight dots, the current one large
    for i in range(1, 9):
        x = 395 + (i-1)*30
        s, e = WIN[i]
        a = [0, max(s, 1e-4), s+.2, e-.2, e, T] if s > 0 else [0, .2, e-.2, e, T]
        rv = '6;6;10;10;6;6' if s > 0 else '6;10;10;6;6'
        ov = '.35;.35;1;1;.35;.35' if s > 0 else '.35;1;1;.35;.35'
        kt = ';'.join(f(x) for x in a)
        out.append(f"<circle cx='{x}' cy='800' r='6' fill='{STEP[i]}' opacity='.35'>"
                   f"<animate attributeName='r' values='{rv}' keyTimes='{kt}' dur='{T}s' repeatCount='indefinite'/>"
                   f"<animate attributeName='opacity' values='{ov}' keyTimes='{kt}' dur='{T}s' repeatCount='indefinite'/></circle>")
    return ''.join(out)

LEFT = "M300,386 C292,280 372,168 458,140"
RIGHT_TO_SERVER = "M716,338 C716,250 640,168 548,140"
C2P = "M300,386 C292,280 372,168 458,140 L548,140 C640,168 716,250 716,338"   # computer -> server -> phone
P2C = "M716,338 C716,250 640,168 548,140 L458,140 C372,168 292,280 300,386"   # phone -> server -> computer

SVG_OPEN = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 -45 1000 865' role='img' aria-labelledby='t'>"
TITLE = ("<title id='t'>Animation of the eight steps of a QR sign-in: the phone scans the QR code, opens a tunnel, "
         "announces itself over Bluetooth, the browser and the phone exchange a handshake through the tunnel, the "
         "browser asks for a signature, you approve on the phone, and the phone sends the signature, after which "
         "the browser is signed in.</title>")

def label_centre(s):
    """centre of a label: its first rect, or a translated group (speech bubbles, icons)"""
    m = re.match(r"<g transform='translate\(([-\d.]+) ([-\d.]+)\)'><rect x='0' y='-23' width='([-\d.]+)'", s)
    if m: return float(m.group(1)) + float(m.group(3)) / 2, float(m.group(2))
    m = re.match(r"<g transform='translate\(([-\d.]+) ([-\d.]+)\)'>", s)
    if m: return float(m.group(1)), float(m.group(2))
    m = re.search(r"<rect x='([-\d.]+)' y='([-\d.]+)' width='([-\d.]+)' height='([-\d.]+)'", s)
    return float(m.group(1)) + float(m.group(3)) / 2, float(m.group(2)) + float(m.group(4)) / 2

# ---- the screens: the computer shows what the browser shows, the phone runs PassKeyChain ----
GREY, YELLOW_, GREEN_ = '#C7C5D0', '#F2B705', '#1E9E5A'

def arrival8():
    """when the signature arrives at the computer (the end of token 8's trip)"""
    return WIN[8][0] + 2.2

def between(a, b, fade=.25):
    """visible from a to b (seconds), invisible otherwise"""
    if a <= 0:
        return (f"<animate attributeName='opacity' values='1;1;0;0' keyTimes='0;{f(b-fade)};{f(b)};1' "
                f"dur='{T}s' repeatCount='indefinite'/>")
    return (f"<animate attributeName='opacity' values='0;0;1;1;0;0' keyTimes='0;{f(a)};{f(a+fade)};{f(b-fade)};{f(b)};1' "
            f"dur='{T}s' repeatCount='indefinite'/>")

def computer_screen(qr_line):
    """steps 1-3 the QR, 4-6 connecting, 7 approve on the phone, 8 access granted (when the 8 arrives)"""
    s4, s7 = WIN[4][0], WIN[7][0]
    a8 = arrival8()
    T_ = lambda x, y, t, size=10, col='#2D2F45', w=800: (f"<text x='{x}' y='{y}' text-anchor='middle' {FONT} "
                                                         f"font-size='{size}' font-weight='{w}' fill='{col}'>{t}</text>")
    bg = "<rect x='220' y='304' width='102' height='78' rx='5' fill='#EEF0FF'/>"
    out = []
    # the QR, back again when the loop restarts
    out.append(f"<g><animate attributeName='opacity' values='1;1;0;0;1;1' keyTimes='0;{f(s4-.1)};{f(s4+.15)};{f(END)};{f(END+.2)};1' "
               f"dur='{T}s' repeatCount='indefinite'/>{qr_line}</g>")
    # connecting to your phone
    out.append(f"<g opacity='0'>{between(s4, s7)}{bg}"
               "<rect x='263' y='313' width='16' height='27' rx='3.5' fill='none' stroke='#4A52B8' stroke-width='2.4'/>"
               "<g fill='#4A52B8'>" + ''.join(
                   f"<circle cx='{259 + j*8}' cy='326.5' r='1.8'><animate attributeName='opacity' values='.2;1;.2' "
                   f"dur='1s' begin='{j*.33:.2f}s' repeatCount='indefinite'/></circle>" for j in (-1, 3)) + "</g>"
               + T_(271, 357, 'Connecting to') + T_(271, 370, 'your phone…') + "</g>")
    # approve on your phone
    out.append(f"<g opacity='0'>{between(s7, a8)}{bg}"
               f"<circle cx='271' cy='328' r='13' fill='{STEP[7]}'/>"
               "<g transform='translate(271 326)' stroke='#1B1B21' stroke-width='1.8' fill='none' stroke-linecap='round'>"
               "<path d='M-3,4 a3,3 0 0 1 6,0'/><path d='M-6,4 a6,6 0 0 1 12,0'/><path d='M-9,4 a9,9 0 0 1 18,0'/>"
               "<path d='M0,4 v6'/></g>"
               + T_(271, 357, 'Approve on') + T_(271, 370, 'your phone') + "</g>")
    # access granted
    out.append(f"<g opacity='0'>{between(a8, END)}{bg}"
               f"<circle cx='271' cy='328' r='13' fill='{GREEN_}'/>"
               "<path d='M264.5,328.5 l4.5,4.5 l8.5,-9' stroke='#fff' stroke-width='2.8' fill='none' stroke-linecap='round' stroke-linejoin='round'/>"
               + T_(271, 357, 'Access', col=GREEN_) + T_(271, 370, 'granted', col=GREEN_) + "</g>")
    return ''.join(out)

def phone_screen():
    """PassKeyChain on the phone: the scanned QR above, the eight steps below, live"""
    a8 = arrival8()
    o = ["<g transform='rotate(-10 712 300)'>",
         "<rect x='684' y='250' width='56' height='102' rx='11' fill='#2D2F45'/>",
         "<rect x='689' y='258' width='46' height='86' rx='6' fill='#F7F5FF'/>",
         "<path d='M695,258 h34 a6,6 0 0 1 6,6 v34 h-46 v-34 a6,6 0 0 1 6,-6 Z' fill='#3B3F4A'/>",     # the camera picture
         "<rect x='702' y='268' width='20' height='20' rx='1.5' fill='#fff'/>"]
    q = "<g fill='#1B1B21'>"
    for fx, fy in ((703.5, 269.5), (715.5, 269.5), (703.5, 281.5)):                               # finder patterns
        q += f"<rect x='{fx}' y='{fy}' width='5' height='5'/><rect x='{fx+1}' y='{fy+1}' width='3' height='3' fill='#fff'/><rect x='{fx+1.8}' y='{fy+1.8}' width='1.4' height='1.4'/>"
    for mx, my in ((710.5, 270), (712, 273), (710.5, 276.5), (713.5, 278), (716, 282), (719, 283.5), (711, 283), (717.5, 277), (720, 280)):
        q += f"<rect x='{mx}' y='{my}' width='1.6' height='1.6'/>"
    o.append(q + "</g>")
    # the stamp's frame around the QR: yellow while verifying, green when approved
    o.append(f"<rect x='700' y='266' width='24' height='24' rx='3' fill='none' stroke='{YELLOW_}' stroke-width='1.8' opacity='0'>"
             f"{between(WIN[2][0], a8, .1)}</rect>")
    o.append(f"<rect x='700' y='266' width='24' height='24' rx='3' fill='none' stroke='{GREEN_}' stroke-width='1.8' opacity='0'>"
             f"{between(a8, END, .1)}</rect>")
    # the checklist: grey, yellow while busy, green when done
    for i in range(1, 9):
        y = 303 + (i-1)*5.1
        s0, e0 = WIN[i]
        if i == 8: e0 = a8
        if s0 > 0:
            vals, kts = f"{GREY};{YELLOW_};{GREEN_};{GREY}", f"0;{f(s0)};{f(e0)};{f(END)}"
        else:
            vals, kts = f"{YELLOW_};{GREEN_};{GREY}", f"0;{f(e0)};{f(END)}"
        o.append(f"<circle cx='694' cy='{y:.1f}' r='1.7' fill='{GREY}'>"
                 f"<animate attributeName='fill' values='{vals}' keyTimes='{kts}' calcMode='discrete' dur='{T}s' repeatCount='indefinite'/></circle>"
                 f"<rect x='698' y='{y-0.7:.1f}' width='{26 - (i % 3) * 5}' height='1.4' rx='.7' fill='#9A98A8'/>")
    o.append("</g>")
    return ''.join(o)

def build_scene(k=1.0):
    """the illustration with its animations; labels scaled by k around their own centres"""
    def lab(*ns, kk=None, dx=0, dy=0):
        body = ''.join(line(n) for n in ns)
        kk = k if kk is None else kk
        if kk == 1.0 and dx == 0 and dy == 0: return body
        cx, cy = label_centre(line(ns[0]))
        return (f"<g transform='translate({cx+dx:.1f} {cy+dy:.1f}) scale({kk}) translate({-cx:.1f} {-cy:.1f})'>{body}</g>")
    o = []
    o += L[2:16]                                   # lines 3-16: decoration and the server
    o.append(wrap(4, line(17) + line(18)))         # browser's side of the tunnel: step 4
    o.append(wrap(2, line(19) + line(20)))         # phone's side of the tunnel: step 2
    o.append(line(21))                             # <g transform='translate(0 90)'>
    o.append(wrap(1, line(22) + line(23)))         # QR beam
    o.append(wrap(3, ''.join(line(n) for n in range(24, 29))))  # Bluetooth arcs
    o += [line(n) for n in range(29, 33)]          # desk, person, the laptop
    o.append(computer_screen(line(33)))            # what the browser shows
    o += [line(n) for n in range(34, 51)]          # people
    o.append(phone_screen())                       # PassKeyChain on the phone (replaces line 51)
    o.append(line(52))                             # the fingers holding it
    o.append(wrap(1, lab(53, 54)))                 # "QR code" label and badge
    o.append(wrap(3, lab(55, 56)))                 # "Bluetooth" label and badge
    o += [lab(57), lab(58), line(59)]              # Browser, PassKeyChain, </g>
    o.append(lab(60))                              # Tunnel server label
    # "Encrypted tunnel" label, badge 2; when enlarged, moved up into free space
    o.append(wrap(2, lab(61, 62) if k == 1.0 else lab(61, 62, kk=1.2, dx=14, dy=-58)))
    o.append(wrap(4, lab(63)))                     # Hello
    o.append(wrap(5, lab(65)))                     # Hello back
    o.append(wrap(6, lab(64)))                     # Sign this?
    o.append(wrap(7, lab(67, 68)))                 # fingerprint on the phone: you approve
    o.append(wrap(8, lab(66)))                     # Signature
    o.append(wrap(8, lab(69, 70)))                 # Signed in
    # moving parts
    o.append(token(1, "M318,478 L690,428", k=k))   # just below the beam, clear of its label
    o.append(token(2, RIGHT_TO_SERVER, k=k))
    o.append(ripples(690, 470, 3))
    # the broadcast itself, from the phone to the computer, under the "Bluetooth" label
    o.append(token(3, "M650,596 Q515,622 385,590", k=k))
    o.append(token(4, C2P, k=k))
    o.append(token(5, P2C, k=k))
    o.append(token(6, C2P, k=k))
    o.append(ripples(896, 282, 7, n=3, reach=60, start=28))   # the unlock, at the fingerprint
    o.append(token(8, P2C, travel=(WIN[8][0], WIN[8][0] + 2.2), k=k))
    return o

o = [SVG_OPEN, TITLE] + build_scene()
scene = o[1:]          # everything after the <svg> tag

# ---- tall version (phones): the scene with one caption and progress dots below ----
tall = [o[0]] + scene + [captions(), "</svg>"]
open(out_anim, 'w').write('\n'.join(tall))

# ---- wide version (desktops): the eight steps listed to the right of the scene ----
SIDE = {1: ('Scan the QR, derive keys', 'Computer → phone · QR code'),
        2: ('Set up the tunnel', 'Phone → tunnel server'),
        3: ('Tell the browser where to go', 'Phone → computer · Bluetooth'),
        4: ('The browser starts the handshake', 'Computer → tunnel → phone'),
        5: ('The phone answers the handshake', 'Phone → tunnel → computer'),
        6: ('The browser asks for a signature', 'Computer → phone · tunnel'),
        7: ('You approve', 'On the phone · fingerprint, face or PIN'),
        8: ('The phone sends the signature', 'Phone → computer → website')}

def side_panel(x0=1030, y0=-28, w=440, row=86, hgt=76):
    out = []
    for i in range(1, 9):
        y = y0 + (i-1)*row
        s0, e0 = WIN[i]
        # waiting dim, current bright, done half; everything resets with the loop
        if s0 > 0:
            vals, kts = '.38;.38;1;1;.62;.62;.38', [0, s0, s0+.25, e0-.1, e0+.15, END, T]
        else:
            vals, kts = '1;1;.62;.62;.38', [0, e0-.1, e0+.15, END, T]
        kt = ';'.join(f(k) for k in kts)
        frame_vals = '0;0;1;1;0;0' if s0 > 0 else '1;1;0;0'
        frame_kts = [0, s0, s0+.25, e0-.1, e0+.15, T] if s0 > 0 else [0, e0-.1, e0+.15, T]
        out.append(f"<g opacity='.38'><animate attributeName='opacity' values='{vals}' keyTimes='{kt}' dur='{T}s' repeatCount='indefinite'/>"
                   f"<rect x='{x0}' y='{y}' width='{w}' height='{hgt}' rx='22' fill='#fff' stroke='#00000014'/>"
                   f"<rect x='{x0}' y='{y}' width='{w}' height='{hgt}' rx='22' fill='none' stroke='{STEP[i]}' stroke-width='4' opacity='0'>"
                   f"<animate attributeName='opacity' values='{frame_vals}' keyTimes='{';'.join(f(k) for k in frame_kts)}' dur='{T}s' repeatCount='indefinite'/></rect>"
                   f"<circle cx='{x0+40}' cy='{y+hgt/2}' r='21' fill='{STEP[i]}'/>"
                   f"<text x='{x0+40}' y='{y+hgt/2+8}' text-anchor='middle' {FONT} font-size='22' font-weight='800' fill='{INK(i)}'>{i}</text>"
                   f"<text x='{x0+76}' y='{y+33}' {FONT} font-size='21' font-weight='700' fill='#1B1B21'>{SIDE[i][0]}</text>"
                   f"<text x='{x0+76}' y='{y+58}' {FONT} font-size='16' font-weight='600' fill='#6b6880'>{SIDE[i][1]}</text></g>")
    return ''.join(out)

# ---- phone version: larger labels, and a big caption card for the current step ----
PHONE_TEXT = {1: 'The phone reads the QR with its camera. Both sides now derive the same keys.',
              2: 'The phone connects to the tunnel server on the internet and reserves a meeting room.',
              3: 'A short, encrypted Bluetooth broadcast tells the computer where to meet.',
              4: 'The computer joins the meeting room and starts an encrypted handshake.',
              5: 'The phone answers. From now on everything is encrypted end to end.',
              6: 'The name of the website and a random challenge arrive on the phone.',
              7: 'The phone shows the site and the account. You unlock to say yes.',
              8: 'The phone signs the challenge, the website checks it: you are in!'}

def phone_captions(y0=735):
    import textwrap
    out = [f"<rect x='24' y='{y0}' width='952' height='400' rx='44' fill='#fff' stroke='#00000014'/>"]
    for i in range(1, 9):
        title = textwrap.wrap(SIDE[i][0], 22)
        body = textwrap.wrap(PHONE_TEXT[i], 37)
        g = [f"<g opacity='0'>{only_during(i)}",
             f"<circle cx='110' cy='{y0+92}' r='50' fill='{STEP[i]}'/>",
             f"<text x='110' y='{y0+110}' text-anchor='middle' {FONT} font-size='52' font-weight='800' fill='{INK(i)}'>{i}</text>"]
        for j, t in enumerate(title):
            g.append(f"<text x='190' y='{y0+82+j*56 - (len(title)-1)*28 + 18}' {FONT} font-size='50' font-weight='800' fill='#1B1B21'>{t}</text>")
        for j, t in enumerate(body):
            g.append(f"<text x='70' y='{y0+228+j*58}' {FONT} font-size='45' font-weight='500' fill='#4a4760'>{t}</text>")
        g.append("</g>")
        out.append(''.join(g))
    for i in range(1, 9):   # progress dots
        x = 290 + (i-1)*60
        s0, e0 = WIN[i]
        a = [0, max(s0, 1e-4), s0+.2, e0-.2, e0, T] if s0 > 0 else [0, .2, e0-.2, e0, T]
        rv = '11;11;19;19;11;11' if s0 > 0 else '11;19;19;11;11'
        ov = '.35;.35;1;1;.35;.35' if s0 > 0 else '.35;1;1;.35;.35'
        kt = ';'.join(f(x_) for x_ in a)
        out.append(f"<circle cx='{x}' cy='{y0+455}' r='11' fill='{STEP[i]}' opacity='.35'>"
                   f"<animate attributeName='r' values='{rv}' keyTimes='{kt}' dur='{T}s' repeatCount='indefinite'/>"
                   f"<animate attributeName='opacity' values='{ov}' keyTimes='{kt}' dur='{T}s' repeatCount='indefinite'/></circle>")
    return ''.join(out)

out_phone = sys.argv[5] if len(sys.argv) > 5 else None
if out_phone:
    set_timing(PHONE_STEP_SECONDS)
    phone = [SVG_OPEN.replace("viewBox='0 -45 1000 865'", "viewBox='0 -45 1000 1265'"), TITLE] + build_scene(1.4) + [phone_captions(), "</svg>"]
    open(out_phone, 'w').write('\n'.join(phone))
    set_timing(STEP_SECONDS)

if out_wide:
    wide = [o[0].replace("viewBox='0 -45 1000 865'", "viewBox='0 -45 1500 750'")] + scene + [side_panel(), "</svg>"]
    open(out_wide, 'w').write('\n'.join(wide))
print("ok", len('\n'.join(tall)))
