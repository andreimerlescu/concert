# Concert — The 3-Minute 33-Second Waiting Room Story (`0:00`–`3:33` / `213s`)

> **Purpose:** Production-ready Google AI video generation blueprint (Google Veo / Flow / Google AI Studio), brand visual bible, sound & tempo score, timed voiceover script, and YouTube Cinema deployment guide for Concert's built-in **Waiting Room Studio** (`layout: youtube`).
>
> **Exact Runtime:** **3 minutes 33 seconds (`213 seconds`)** across **13 cinematic beats**.
> **Core Message for Waiting Visitors:** *"Your place is saved. Stay calm, enjoy the rhythm, and enter automatically—or use Crypto Fast-Lane / NFT VIP right beside this stream to step straight to the front."*

---

## 1. Brand Identity Foundation (Grounded in `brand-identity-builder`)

### 1.1 Brand Strategy
- **Brand Purpose:** Replace the anxiety of crashing websites, frantic reload loops, and broken `503` error walls with calm, provably fair admission for both humans and AI agents.
- **Target Audience (In-Room Viewers):** High-intent fans, shoppers, attendees, traders, and developers currently waiting in a Concert Waiting Room during a high-demand launch, drop, or traffic surge.
- **Positioning Statement:**
  > *For visitors and operators facing intense traffic surges who refuse to settle for crashing checkout pages and unfair bot stampedes, **Concert** is a velvet-rope traffic conductor that holds every place in strict FIFO order and protects the site behind the curtain—offering free automatic entry alongside optional instant crypto Fast-Lane and NFT VIP access.*
- **Brand Archetype:** **The Maestro** (blending *The Ruler*'s calm architectural order with *The Caregiver*'s transparent hospitality).
- **Brand Personality (4 Adjectives):** Composed · Rhythmic · Fair · Luminous.
- **Voice & Tone:** Warm, unhurried, reassuring, never salesy or pushy. Always emphasize that **standard admission in line is 100% free**; crypto Fast-Lane and NFT VIP are framed strictly as optional express doors.

### 1.2 Visual Style Bible (1:1 Alignment with Concert's Waiting Room CSS Tokens)

The film transitions visually between two signature palettes lifted directly from `internal/server/web/waiting.css`:

| Visual Realm | Palette Anchor | Exact Hex Codes | Emotional Meaning |
|---|---|---|---|
| **Act I: The Broken Web (Chaos)** | Overloaded Crimson & Harsh Fluorescent Static | `#1a0d0d` dark charcoal, `#8c1d12` / `#f85149` alert red, `#ff6b35` thermal amber, harsh white flicker | Overwhelmed servers, 503 walls, frantic F5 refresh fatigue |
| **Act II–III: The Concert Foyer (Order)** | Editorial **Paper** + Velvet **SynthWave '84** Stage | `#f2e8d2` warm cream paper, `#1b1712` espresso ink, `#262335` deep twilight indigo, `#241b2f` velvet dusk | Architectural hospitality, timeless ticket stub, calm order |
| **Act III: Behind the Curtain (Origin)** | Peaceful **Nord / Teal** Infrastructure | `#2e3440` slate rack, `#36f9f6` steady cyan pulse, `#50fa7b` calm emerald heartbeat | Protected origin servers breathing smoothly with zero spikes |
| **Act IV: Fast-Lane & NFT VIP (Choice)** | Luminous **Electric Cyan** & **Warm Stage Gold** | `#36f9f6` electric cyan beam, `#ff7edb` magenta stage rim-light, `#fede5d` warm brass/gold spotlight | Instant settlement, VIP velvet rope, effortless entry |

### 1.3 Graphic Motifs & Diegetic Continuity Rules
1. **The Four-Bar Equalizer Mark (`concert.`):** Four vertical luminous bars pulsing gently in time with the music (matching `<span class="brand-bars">` in `waiting.html`).
2. **The Physical-Digital Ticket Stub:** Perforated warm cream ticket cards (`#f2e8d2`) with crisp dark numerals (`#482 → #120 → #3 → #2 → #1`) that glide smoothly forward along golden floor tracks.
3. **No Garbled AI Text:** Never rely on video generation models to render dense paragraphs of text. Use clean symbolic visuals, single short numerals (`503`, `01`, `02`, `03`, `#1`), and composite sharp vector lower-thirds/logos (`concert.`, chain marks for XRPL / Stellar / Hedera / Solana) in post-production.
4. **Camera & Lens Grammar:** Shot on virtual 35mm anamorphic cinema lens (`24 fps`), gentle Steadicam glides once Concert takes over (contrasted with handheld jitter in Act I), subtle volumetric stage dust, shallow depth of field (`f/2.0`), zero strobe flashing (WCAG photosensitive safety).

---

## 2. 16:9 Framing Safe-Zones for Concert's Waiting Room Cinema Layout

In `internal/server/web/waiting.css`, `[data-layout="youtube"]` places the video inside `.cinema-frame` (`aspect-ratio: 16/9`, `border-radius: 16px`, `1.65fr` left column on desktop beside the `0.95fr` live FIFO ticket panel; stacked above the ticket panel on mobile). Visitors can also open the **Crypto Fast-Lane & NFT VIP Drawer** (`#fastlane-drawer`) from the right side without interrupting playback.

Compose **all** key subjects and post-production callouts strictly inside the inner **Action/Title Safe Zone**:

```text
+------------------------------------------------------------------------+
| [Top 10%: YouTube title bar & rounded 16px corner crop — KEEP CLEAR]   |
|   +----------------------------------------------------------------+   |
|   | [Left 5%]                                          [Right 10%] |   |
|   |             PRIMARY ACTION & SUBJECT SAFE ZONE                 |   |
|   |         (Center 80% Width x Center 70% Height)                 |   |
|   |                                                                |   |
|   |     Place conductor, ticket stubs, server heartbeat,           |   |
|   |     and 4-chain Fast-Lane visuals squarely here.               |   |
|   |                                                                |   |
|   |   [Subtitle/Caption Safe Band: Bottom 18%–26% from edge]       |   |
|   +----------------------------------------------------------------+   |
| [Bottom 15%: YouTube scrub bar, controls & mute icon — KEEP CLEAR]     |
+------------------------------------------------------------------------+
```

- **Muted Autoplay Resilience:** Many waiting visitors watch muted on desktop or mobile. Every beat must be **100% self-explanatory visually** with burned-in or `.srt` closed captions positioned in the lower-middle band (`18%–26%` up from bottom edge, clearing the YouTube scrub bar).

---

## 3. Sound Design & Musical Tempo Arc (`0:00`–`3:33`)

- **Loudness Target:** `-14 LUFS` integrated, `-1.0 dBTP` true peak (YouTube broadcast standard).
- **Voiceover Profile:** Warm, composed, gender-neutral or warm baritone/alto documentary narrator, ~135–145 WPM with intentional 1.5–2.0s breathing pauses between acts.

| Act & Timecode | Duration | Tempo (BPM) | Key / Harmony | Musical & SFX Layering |
|---|---|---|---|---|
| **Act I:** `0:00`–`0:45` | 45s | `138 BPM` (erratic) | D minor (tense, unresolved) | Staccato ticking clocks, overlapping browser click/refresh chatter, muffled server fan whine, distant low-pass static hiss; abrupt silence at `0:44.5`. |
| **Act II:** `0:45`–`1:35` | 50s | `76 BPM` (steady) | F major / D minor9 (warm) | Single resonant cello bow + warm Fender Rhodes electric piano chords; soft brass velvet-rope latch click; gentle rhythmic pulse matching an orderly heartbeat. |
| **Act III:** `1:35`–`2:20` | 45s | `84 BPM` (flowing) | F major → Bb lydian | Subtle marimba arpeggios (representing AI agents moving in clean rhythmic intervals) braided with human acoustic strings; quiet, airy server-room hum like calm breathing. |
| **Act IV:** `2:20`–`3:05` | 45s | `92 BPM` (luminous) | C major / G mixolydian | Shimmering analog synth pads (`SynthWave '84` warmth without harshness), four delicate crystalline chimes as XRPL, Stellar, Hedera, and Solana lanes illuminate; velvet chime for NFT VIP. |
| **Act V:** `3:05`–`3:33` | 28s | `96 → 80 BPM` (resolving) | F major (grand open fifth) | Three crisp acoustic woodblock/piano countdown notes (`3`, `2`, `1`), warm orchestral swell as doors open into light, clean resolving chord fading gently to silence at `3:33.0`. |

---

## 4. Ready-to-Paste Master Director Prompt (Google AI Video / Veo Style Anchor)

Paste this master prompt as the project-level style Bible / system brief in Google Flow / Veo before generating the 13 individual segments below:

```text
Cinematic 16:9 widescreen film (24fps, 35mm anamorphic lens, shallow depth of field, subtle film grain, zero strobe flicker). A refined visual story set in an architectural modern concert hall that serves as a metaphor for fair internet traffic orchestration ("Concert").

Visual continuity rules:
- Act I (0:00-0:45): Overcrowded dark industrial corridor with harsh crimson (#8c1d12) alert reflections, swirling glass browser shards, and overheating dark server racks under chaotic handheld camera motion.
- Act II-V (0:45-3:33): Smooth Steadicam gliding motion inside a breathtaking twilight velvet-and-cream architectural foyer (#262335 deep indigo walls, #f2e8d2 warm cream stone, #fede5d warm brass spotlights, #36f9f6 luminous cyan floor guide-rails, #ff7edb subtle magenta horizon rim-light).
- Recurring hero motifs: a composed conductor in dark tailored attire using gentle baton arcs (never frantic); tactile warm-cream numbered ticket stubs floating calmly along glowing floor lanes; friendly translucent geometric light-silhouettes representing AI agents standing respectfully beside diverse real people; and a serene, cool-teal glass sanctuary behind a velvet curtain where pristine origin servers pulse slowly and peacefully.
- Framing: Keep all primary action, faces, and symbolic focal points within the inner 80% horizontal and 70% vertical safe zone so bottom video player controls never obscure the story. Do not render cluttered background text; keep surfaces minimalist and clean.
```

---

## 5. Shot-by-Shot Storyboard, Prompts & Timed Voiceover (`0:00`–`3:33` = `213s`)

> **Timing Audit:** `10 + 15 + 20 + 10 + 20 + 20 + 20 + 20 + 15 + 20 + 15 + 18 + 10 = 213 seconds (3:33 exact).`

### Act I — The Chaos Before Concert (`0:00`–`0:45` · `45s`)

#### Beat 01 · `0:00`–`0:10` (`10s`) — The Stampede Begins
- **Google AI Video Prompt:**
  > Wide anamorphic establishing shot, 24fps, slight handheld tension. Thousands of bright light streaks and rushing silhouettes funnel violently toward a single narrow glass doorway at the end of a dark concrete tunnel. Deep charcoal shadows (#1a0d0d) pierced by harsh amber and crimson warning reflections (#8c1d12). Dust motes scatter as the doorway trembles under pressure. Center-framed composition inside 80% safe zone. No text.
- **Audio Cue:** `138 BPM` restless ticking pulse; rising crowd murmur.
- **Voiceover (`0:02`–`0:09`):**
  > *"You know this moment. A big launch goes live—and a hundred thousand doors slam open at once."*

#### Beat 02 · `0:10`–`0:25` (`15s`) — The 503 Wall & Refresh Storm
- **Google AI Video Prompt:**
  > Medium close-up tracking shot across a dark glass corridor. Dozens of glowing circular loading spinners stall and shatter like frosted glass against an imposing crimson light barrier (#8c1d12). Reflections of frustrated hands tapping keyboards and phones ripple across wet slate floors. Restrained lighting—no harsh strobing—just heavy, pulsing red congestion and deadlocked motion. Center-weighted framing.
- **Audio Cue:** Rhythmic impatient click-clack of refresh storms; low resonant thud as the red wall seals shut.
- **Voiceover (`0:11`–`0:24`):**
  > *"Pages freeze. Everyone hits refresh faster and faster—turning a crowd of excited visitors into an accidental storm that locks everyone out behind a wall of errors."*

#### Beat 03 · `0:25`–`0:45` (`20s`) — The Origin Server Under Siege
- **Google AI Video Prompt:**
  > Slow push-in inside a dark server vault behind the glass wall. Rows of matte-black server racks glow angry thermal orange and red as frantic waves of red light pulses slam into their glass faceplates. Cooling fans spin violently in dramatic slow motion; warm heat-haze rises above the cabinets. At 18 seconds, the red storm abruptly freezes in mid-air as a single pure beam of warm gold light (#fede5d) slices downward from above, silencing the chaos.
- **Audio Cue:** Whirring fan crescendo suddenly cut to a dramatic half-second breath of total silence at `0:44.5`.
- **Voiceover (`0:26`–`0:43`):**
  > *"Behind the scenes, the website's own servers take the brunt of it—drowning in retries instead of serving the people who actually made it inside. There is a better way to open the doors."*

---

### Act II — Enter the Velvet-Rope Orchestra (`0:45`–`1:35` · `50s`)

#### Beat 04 · `0:45`–`0:55` (`10s`) — The Velvet Rope Drops
- **Google AI Video Prompt:**
  > Seamless architectural transformation, smooth Steadicam glide, 24fps. The harsh concrete tunnel dissolves effortlessly into a grand, serene modern concert hall foyer bathed in twilight indigo (#262335) and warm cream architectural stone (#f2e8d2). A rich crimson-and-brass velvet rope lowers gracefully into place while four luminous vertical equalizer bars rise softly on a dark glass pillar. Calm warm gold key light (#fede5d).
- **Audio Cue:** Single deep cello note resolves into warm Rhodes chords at `76 BPM`; crisp brass latch click.
- **Voiceover (`0:46`–`0:54`):**
  > *"Welcome to Concert. Before a single request reaches the stage, the storm becomes a symphony."*

#### Beat 05 · `0:55`–`1:15` (`20s`) — The Concert Hall Foyer & FIFO Ticket
- **Google AI Video Prompt:**
  > Graceful orbiting Steadicam shot inside the luminous twilight concert foyer. A composed conductor in dark minimal attire stands on a low circular dais, gently guiding glowing paths along the floor with a calm sweep of the hand. Diverse, relaxed visitors stroll into spacious illuminated lanes; a crisp, warm-cream physical-digital ticket card (#f2e8d2) materializes gently in a visitor's hand, glowing with soft brass edges as every person takes an orderly, numbered place in line. Shallow depth of field, warm editorial elegance.
- **Audio Cue:** Steady acoustic upright bass and soft percussion join at `76 BPM`; tactile paper-ticket shimmer.
- **Voiceover (`0:56`–`1:13`):**
  > *"Every visitor receives a signed, first-in, first-out place in line. No tricks, no luck of the reload button, and no cutting ahead in the dark. Your spot is locked in the moment you arrive."*

#### Beat 06 · `1:15`–`1:35` (`20s`) — Rhythm Without Refreshing (Live ETA & Global Reach)
- **Google AI Video Prompt:**
  > Smooth dolly shot moving alongside relaxed people waiting in warm lounge alcoves—one sipping coffee at a café table, another smiling on a laptop in Tokyo dusk, another checking a phone in a sunlit courtyard. Subtle translucent cyan light ribbons (#36f9f6) drift gently past them like musical measures, showing steady forward progress without anyone tapping refresh. Warm balanced exposure, center-safe framing, harmonious transitions.
- **Audio Cue:** Gentle harp and string swells; serene rhythmic metronome pulse.
- **Voiceover (`1:16`–`1:33`):**
  > *"You never need to refresh this page. Concert measures real admission speed live, updates your wait time automatically, and speaks nineteen languages—so wherever you are in the world, you can simply relax while your turn glides closer."*

---

### Act III — Humans & AI Agents in Fair Harmony + The Peaceful Origin (`1:35`–`2:20` · `45s`)

#### Beat 07 · `1:35`–`1:55` (`20s`) — Humans & AI Agents in Fair Harmony
- **Google AI Video Prompt:**
  > Wide architectural tracking shot across two parallel luminous floor paths in the grand foyer. On the left path, real human visitors walk at an easy, unhurried pace under warm golden light (#fede5d). On the right path, sleek, friendly translucent glass-and-cyan geometric light-figures (#36f9f6)—representing autonomous AI agents—wait politely in clean, evenly spaced intervals holding crystalline pass tokens. Neither lane pushes or crowds the other; a subtle glowing boundary keeps aggressive dark shadow-sparks calmly outside the outer glass doors.
- **Audio Cue:** Tempo lifts gently to `84 BPM`; playful clean marimba arpeggios interweave with warm strings.
- **Voiceover (`1:36`–`1:53`):**
  > *"Today's web isn't only humans—autonomous AI agents are lining up too. Concert keeps both worlds in harmony: abusive floods are stopped at the door, while respectful agents wait cleanly by the rules or bid transparently for open passes."*

#### Beat 08 · `1:55`–`2:15` (`20s`) — Behind the Curtain: The Breathing Origin
- **Google AI Video Prompt:**
  > Dreamlike Steadicam push through a tall, sheer dark-velvet theater curtain into a peaceful glass sanctuary behind the foyer. The exact same server racks from Act I now look pristine, cool, and serene—bathed in calm slate (#2e3440), soft cyan (#36f9f6), and steady emerald (#50fa7b) indicator lights pulsing in slow, synchronized waves like calm breathing. One luminous stream of visitors enters gracefully at a measured tempo through an arched portal; zero red lights, zero strain.
- **Audio Cue:** Airy ambient pad; soft synchronized rhythmic swell mimicking calm breathing.
- **Voiceover (`1:56`–`2:13`):**
  > *"Step behind the curtain, and you'll see why this works. Instead of collapsing under a sudden tidal wave, the site ahead breathes at its exact healthy capacity—so when your turn arrives, every page, cart, and checkout loads fast and clean."*

---

### Act IV — Two Ways In: Enjoy the Wait, or Crypto Fast-Lane / NFT VIP (`2:15`–`3:05` · `50s`)

#### Beat 09 · `2:15`–`2:30` (`15s`) — Choice Without Pressure (Free Standard Queue)
- **Google AI Video Prompt:**
  > Medium shot returning to the warm concert foyer. A calm wide staircase bathed in cream and warm gold leads steadily forward to the main auditorium doors. To the right, an architectural side-arch glows softly in electric cyan (#36f9f6) and violet (#ff7edb), labeled only by a subtle lightning-bolt prism icon. A visitor looks peacefully at both paths—completely unhurried, in full control. Center-safe framing.
- **Audio Cue:** Tempo glides smoothly to `92 BPM`; open, inviting major-seventh piano voicing.
- **Voiceover (`2:16`–`2:29`):**
  > *"Your standard place in line is always free—just keep this tab open and enjoy the countdown. And if you're in a hurry, Concert offers an optional express door right beside this stream."*

#### Beat 10 · `2:30`–`2:50` (`20s`) — Crypto Fast-Lane: XRPL, Stellar, Hedera, Solana
- **Google AI Video Prompt:**
  > Sleek cinematic motion-design sequence inside the luminous cyan express gallery (#241b2f background, #36f9f6 cyan light paths, #fede5d gold accents). Four distinct streams of crystalline light converge cleanly into a single glowing prism arch—representing four fast, non-custodial settlement rails (post-production overlays cleanly label XRPL, Stellar, Hedera, and Solana beside each stream). A minimalist glowing keycard materializes instantaneously with a soft ripple of cyan light, no middlemen, no waiting for bank clearing. Keep lower 15% and right 10% clear for player/drawer safe zones.
- **Audio Cue:** Four delicate crystalline chime notes ascending in pitch as each of the four light streams locks into the arch.
- **Voiceover (`2:31`–`2:49`):**
  > *"Open the Crypto Fast-Lane drawer without ever leaving this video. Settle directly from your own wallet in seconds over XRPL, Stellar, Hedera, or Solana—non-custodial, verified on-chain, and ready the instant it clears."*

#### Beat 11 · `2:50`–`3:05` (`15s`) — NFT VIP Bypass: Zero Interruption
- **Google AI Video Prompt:**
  > Elegant close-up to medium shot at a velvet-draped VIP archway glowing with warm gold (#fede5d) and soft magenta rim-light (#ff7edb). A visitor presents a luminous geometric holographic medallion (representing an eligible NFT membership pass). The brass velvet rope glides silently open on its own as the medallion shimmers once in confirmation, ushering the visitor straight into the illuminated hall while the main foyer stream remains visible in soft background bokeh.
- **Audio Cue:** Warm brass chime + soft velvet glide; music builds gently toward the finale.
- **Voiceover (`2:51`–`3:04`):**
  > *"Already hold an eligible community NFT? Switch to the VIP tab, prove ownership with a single signature, and walk straight past the velvet rope—no payment required."*

---

### Act V — Doors Open: Your Turn (`3:05`–`3:33` · `28s`)

#### Beat 12 · `3:05`–`3:23` (`18s`) — Countdown to Admission (`#3 → #2 → #1`)
- **Google AI Video Prompt:**
  > Uplifting Steadicam forward glide down the center aisle of the twilight concert foyer toward two monumental warm-bronze and glass double doors. Soft golden spotlights (#fede5d) and cyan guide lights (#36f9f6) illuminate in three rhythmic waves toward the threshold as the conductor lowers the baton with a welcoming nod. Warm cinematic bloom spills from the seam between the doors as they begin to part.
- **Audio Cue:** Three crisp, resonant piano/woodblock pulses (`3`… `2`… `1`), orchestral strings swell warmly into an open F-major chord.
- **Voiceover (`3:06`–`3:21`):**
  > *"Whether you ride the rhythm of the room or take the express lane, everyone steps through to a site that's fast, fair, and ready for you. Three… two… one—your turn is coming up."*

#### Beat 13 · `3:23`–`3:33` (`10s`) — Doors Open & Brand End-Card (`concert.`)
- **Google AI Video Prompt:**
  > Grand double doors swing smoothly wide open into radiant warm cream-and-gold daylight (#f2e8d2 / #fede5d), camera gliding gently through the threshold before settling onto a clean, serene deep-indigo stage backdrop (#262335) with four minimalist vertical equalizer bars gently breathing in the center safe zone (post-production places crisp `concert.` wordmark and tagline: "Order in the queue. Energy in the room."). Smooth fade-out at 3:33.
- **Audio Cue:** Warm resolving orchestral chord + Rhodes shimmer decays cleanly to silence at `3:33.0`.
- **Voiceover (`3:24`–`3:31`):**
  > *"Concert. Order in the queue. Energy in the room."*

---

## 6. Post-Production Polish Checklist

Before uploading the final `3:33` master render (`1920×1080` or `3840×2160`, `24fps`, H.264/HEVC MP4, AAC 320 kbps):

1. **Vector Title Cards & Badges:** Composite clean vector overlays inside the 80%×70% safe zone for:
   - Beat 02: subtle `503` badge shatter
   - Beat 05: `01 Fair by default · 02 Automatic entry · 03 No refresh needed`
   - Beat 10: clean chain labels (`XRPL`, `Stellar`, `Hedera`, `Solana`)
   - Beat 12: crisp `#3 → #2 → #1 → ADMITTED` progression
   - Beat 13: `concert.` wordmark + *"Order in the queue. Energy in the room."*
2. **Closed Captions (`.srt` / `.vtt`):** Export English captions first, then translate into Concert's 19 supported locales (including RTL `ar`, `he`, `fa`, `arc`) so muted autoplay viewers anywhere in the world follow effortlessly.
3. **Loop-Friendly Ending:** Keep the final 2 seconds clean and quiet so if YouTube loops or pauses on the end frame, the `concert.` emblem sits crisply inside `.cinema-frame`.

---

## 7. Upload to YouTube & Set as Default in Concert Waiting Room

Concert's Waiting Room Studio embeds YouTube exclusively via **`https://www.youtube-nocookie.com/embed/<id>`** (privacy-enhanced mode, strict CSP `frame-src https://www.youtube-nocookie.com` active **only** on `layout: youtube`, while all other layouts enforce `frame-src 'none'`).

### Step 1: Upload the `3:33` Render to YouTube
1. Sign in to your brand's YouTube Studio and upload the finished `3:33` MP4 (`16:9`, 1080p or 4K).
2. Under **Visibility**, choose **Public** or **Unlisted** (*Private* videos cannot embed for waiting visitors).
3. Under **Show more → License and distribution**, confirm **Allow embedding** is checked.
4. Upload your `.srt` subtitle tracks so muted viewers see captions automatically.
5. Copy the resulting YouTube URL (any standard shape works—`https://www.youtube.com/watch?v=<11-char-id>`, `https://youtu.be/<11-char-id>`, `https://www.youtube.com/live/<11-char-id>`, or the bare 11-character ID).

### Step 2: Configure in Concert's Admin Portal (**Waiting Room** Tab)
1. Open the Concert Admin Portal (`-portal-listen`, default `127.0.0.1:8081`) and sign in with an **Admin** account.
2. Click the **Waiting Room** tab (`Waiting Room & Drop Control`).
3. Inside the **Waiting Room Studio** card:
   - Set **Layout** to **`YouTube Cinema`** (`youtube`).
   - Choose your **Theme** (e.g., `System (Auto)`, `SynthWave '84`, `Paper (Light)`, or any of the 10 WCAG themes) and **Default locale**.
   - Paste your YouTube URL or 11-character video ID into **`YouTube stream / video URL or 11-char ID`**.
   - Confirm the live badge beside the input parses your exact 11-character ID (e.g., `abcDEF123_-`) and the **Active Content-Security-Policy** preview displays:
     `frame-src https://www.youtube-nocookie.com`
4. Click **Save Studio Settings**. Concert validates the ID against `^[A-Za-z0-9_-]{11}$`, persists `<data-dir>/waitingroom.json` atomically (`0600`), records a `waitingroom.update` audit event, and updates waiting visitors immediately—zero restart required.

### Step 3: Swapping Videos via API (Optional Automation)
Operators who want to start with the default 3:33 Concert story video and swap in a live product-drop keynote or event stream later can also update it programmatically via the Admin Portal API (`PUT /api/waitingroom`):

```json
{
  "layout": "youtube",
  "theme": "synthwave84",
  "brand_name": "Concert",
  "default_locale": "en",
  "youtube_url": "https://youtu.be/<YOUR_11_CHAR_VIDEO_ID>"
}
```

- **Want to use Concert's default demo video?** Paste the official Concert `3:33` YouTube ID once published.
- **Want to use your own stream or teaser?** Replace `youtube_url` with any public/unlisted YouTube video or livestream URL (`youtube.com/live/<id>`), or clear the field to display Concert's zero-dependency pure-CSS animated stage placeholder (automatically tightening CSP back to `frame-src 'none'`).
