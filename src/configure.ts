/**
 * The Singularity /configure page - the config UI in VortX's own design language (gold accent, warm
 * near-black canvas, serif title, chips + surface-cards, one gold CTA). Built to docs/DESIGN-SYSTEM.md
 * tokens. It collects NON-SECRET preferences only; debrid/usenet keys live in the VortX account (a note
 * says so). On Save it base64url(JSON)s the config into the add-on manifest URL.
 */
import {
  DEBRID_SERVICES, USENET_SERVICES, RESOLUTIONS, SORT_KEYS,
  FORMAT_PRESETS, HISTORY_SOURCES, DEFAULT_CONFIG,
} from "./config.ts";
import { FORMAT_TEMPLATE_VARS, SOURCE_KINDS } from "./corpus.ts";

// Curated user-facing tag choices (visual / audio / encode; CAM/junk is handled by the Exclude-CAM toggle).
const TAG_CHOICES = ["hdr", "dv", "hdr10plus", "hlg", "10bit", "imax", "remux", "atmos", "truehd", "dtshd", "dts", "ddp", "flac", "av1", "hevc", "avc", "xvid"];
const tagChips = (group: string) =>
  TAG_CHOICES.map((t) => `<label class="chip"><input type="checkbox" data-group="${group}" value="${t}"><span>${t.toUpperCase()}</span></label>`).join("");

// Curated audio-language choices: [slug, display]. Slugs match KNOWN_LANGUAGES_LIST in corpus.ts.
const LANG_CHOICES: Array<[string, string]> = [
  ["en", "English"], ["es", "Spanish"], ["fr", "French"], ["de", "German"], ["it", "Italian"],
  ["pt", "Portuguese"], ["ru", "Russian"], ["hi", "Hindi"], ["ja", "Japanese"], ["ko", "Korean"],
  ["zh", "Chinese"], ["ar", "Arabic"], ["ta", "Tamil"], ["te", "Telugu"], ["nl", "Dutch"],
  ["pl", "Polish"], ["tr", "Turkish"], ["multi", "Multi"], ["dual", "Dual"],
];
const langChips = (group: string) =>
  LANG_CHOICES.map(([s, d]) => `<label class="chip"><input type="checkbox" data-group="${group}" value="${s}"><span>${d}</span></label>`).join("");

const KIND_LABELS: Record<string, string> = { torrent: "Torrent", http: "Direct (HTTP)", nzb: "Usenet (NZB)" };
const kindChips = (group: string) =>
  SOURCE_KINDS.map((k) => `<label class="chip"><input type="checkbox" data-group="${group}" value="${k}"><span>${KIND_LABELS[k] || k}</span></label>`).join("");

const LABELS: Record<string, string> = {
  realdebrid: "Real-Debrid", alldebrid: "AllDebrid", premiumize: "Premiumize", debridlink: "Debrid-Link",
  torbox: "TorBox", offcloud: "Offcloud", putio: "put.io", easydebrid: "EasyDebrid", debrider: "Debrider",
  pikpak: "PikPak", seedr: "Seedr", easynews: "Easynews", nntp: "Usenet (NNTP)", self_hosted: "Self-hosted NZB",
  library: "VortX library", trakt: "Trakt", simkl: "SIMKL",
};
const label = (s: string) => LABELS[s] ?? s.replace(/\b\w/g, (m) => m.toUpperCase());
const checks = (group: string, items: string[], on: string[] = []) =>
  items.map((i) => `<label class="chk"><input type="checkbox" data-group="${group}" value="${i}"${on.includes(i) ? " checked" : ""}><span>${label(i)}</span></label>`).join("");
const resChips = RESOLUTIONS.map((r) => `<label class="chip"><input type="checkbox" data-group="resolutions" value="${r}"><span>${r}</span></label>`).join("");
const resChipsFor = (group: string) => RESOLUTIONS.map((r) => `<label class="chip"><input type="checkbox" data-group="${group}" value="${r}"><span>${r}</span></label>`).join("");
const sortRows = SORT_KEYS.map((k) => `<label class="chk"><input type="checkbox" data-group="sort" value="${k}"${DEFAULT_CONFIG.sort.includes(k) ? " checked" : ""}><span>${k}</span></label>`).join("");
const formatOpts = FORMAT_PRESETS.map((f) => `<option value="${f}"${f === DEFAULT_CONFIG.format ? " selected" : ""}>${label(f)}</option>`).join("");
const historyOpts = HISTORY_SOURCES.map((h) => `<option value="${h}">${label(h)}</option>`).join("");

export function renderConfigurePage(baseUrl: string): string {
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Configure Singularity - the VortX source engine</title>
<style>
  :root{
    --canvas:#15120E; --surface1:#211C16; --surface2:#2D261D; --surface3:#3A3127; --hairline:#403629;
    --textPrimary:#F6F1E9; --textSecondary:#BCB1A1; --textTertiary:#9E9485;
    --accent:#D97706; --accentBright:#F59E0B; --accentSoft:rgba(217,119,6,.18); --onAccent:#0F0D0A; --danger:#DE4856;
    --serif:"Iowan Old Style",Georgia,"Times New Roman",serif;
    --ui:-apple-system,"SF Pro Display","SF Pro Text",system-ui,Segoe UI,Roboto,sans-serif;
    --card:16px; --chip:12px; --control:14px; --rest:0 7px 12px rgba(0,0,0,.32); --glow:0 0 18px rgba(217,119,6,.6);
    --ease:cubic-bezier(.2,.8,.2,1);
  }
  *{box-sizing:border-box} html,body{margin:0}
  body{background:var(--canvas);color:var(--textPrimary);font-family:var(--ui);line-height:1.5;
    -webkit-font-smoothing:antialiased;padding:0 clamp(20px,5vw,60px) 140px}
  .wrap{max-width:940px;margin:0 auto}
  header{padding:48px 0 8px;text-align:center}
  .mark{width:52px;height:52px;margin:0 auto 12px;display:block}
  h1{font-family:var(--serif);font-weight:800;letter-spacing:-1px;font-size:clamp(34px,3vw+1rem,52px);margin:0}
  h1 .x{color:var(--accent)}
  .tagline{color:var(--textSecondary);margin:8px 0 4px;font-size:clamp(16px,.4vw+1rem,18px)}
  .eyebrow{font-size:.74rem;letter-spacing:1.5px;text-transform:uppercase;color:var(--accentBright);font-weight:700}
  section.card{background:var(--surface1);border-radius:var(--card);box-shadow:var(--rest);padding:24px 24px 20px;margin-top:32px}
  section.card h2{font-size:clamp(20px,1.4vw+1rem,26px);font-weight:600;letter-spacing:-.3px;margin:0 0 4px}
  .hint{color:var(--textTertiary);font-size:.95rem;margin:0 0 16px}
  .note{background:var(--accentSoft);border-radius:var(--chip);padding:10px 14px;color:var(--textSecondary);font-size:.9rem;margin:0 0 16px}
  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px}
  .chk{display:flex;align-items:center;gap:10px;background:var(--surface2);border-radius:var(--chip);padding:10px 12px;cursor:pointer;transition:background .18s var(--ease)}
  .chk:hover{background:var(--surface3)} .chk input{accent-color:var(--accent);width:16px;height:16px}
  .chips{display:flex;flex-wrap:wrap;gap:8px}
  .chip{display:inline-flex;align-items:center;gap:8px;background:var(--surface2);border-radius:var(--chip);padding:8px 14px;cursor:pointer;font-size:.95rem}
  .chip input{display:none} .chip:has(input:checked){background:var(--accentSoft);color:var(--accentBright);box-shadow:inset 0 0 0 1px var(--accent)}
  .row{display:flex;flex-wrap:wrap;gap:20px;margin-top:6px}
  .field{display:flex;flex-direction:column;gap:6px;min-width:160px;flex:1}
  label.lbl{font-size:.95rem;font-weight:500;color:var(--textSecondary)}
  input[type=text],input[type=number],textarea,select{background:var(--surface2);color:var(--textPrimary);border:none;border-radius:var(--control);
    padding:11px 13px;font-family:var(--ui);font-size:1rem;outline:none;box-shadow:inset 0 0 0 1px var(--hairline)}
  textarea{min-height:90px;resize:vertical;font-family:ui-monospace,Menlo,monospace;font-size:.85rem}
  input:focus,select:focus,textarea:focus{box-shadow:inset 0 0 0 1px var(--accent)}
  .toggle{display:flex;align-items:center;gap:12px;margin-bottom:6px;cursor:pointer}
  .toggle input{accent-color:var(--accent);width:18px;height:18px}
  .footer{position:fixed;left:0;right:0;bottom:0;background:linear-gradient(to top,var(--canvas) 65%,transparent);padding:18px clamp(20px,5vw,60px) 24px}
  .footer .inner{max-width:940px;margin:0 auto;display:flex;gap:12px;align-items:center;flex-wrap:wrap}
  .btn-primary{background:var(--accent);color:var(--onAccent);border:none;border-radius:var(--control);
    padding:15px 32px;font-weight:700;font-size:1.05rem;cursor:pointer;transition:transform .18s var(--ease),background .18s var(--ease),box-shadow .18s var(--ease)}
  .btn-primary:hover{background:var(--accentBright);box-shadow:var(--glow)} .btn-primary:active{transform:scale(.97)}
  .btn-ghost{background:var(--surface2);color:var(--textPrimary);border:none;border-radius:var(--control);padding:15px 22px;font-weight:600;cursor:pointer}
  .btn-ghost:hover{background:var(--surface3)}
  .url{flex:1;min-width:220px;font-family:ui-monospace,Menlo,monospace;font-size:.82rem;color:var(--textTertiary);
    background:var(--surface1);border-radius:var(--chip);padding:11px 13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  @media (prefers-reduced-motion:reduce){*{transition:none!important}}
</style></head>
<body><div class="wrap">
<header>
  <svg class="mark" viewBox="0 0 100 100" aria-hidden="true"><defs>
    <linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#FBBF24"/><stop offset=".5" stop-color="#F59E0B"/><stop offset="1" stop-color="#D97706"/></linearGradient>
    <linearGradient id="b" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#B45309"/><stop offset="1" stop-color="#7C2D12"/></linearGradient></defs>
    <path d="M22 18 L82 82" stroke="url(#b)" stroke-width="15" stroke-linecap="round"/>
    <path d="M82 18 L18 82" stroke="url(#g)" stroke-width="15" stroke-linecap="round"/>
    <circle cx="50" cy="50" r="7" fill="#FDF6E3"/></svg>
  <div class="eyebrow">The VortX source engine</div>
  <h1>Singularit<span class="x">y</span></h1>
  <p class="tagline">One add-on for every source - your debrid + Usenet + add-ons, the crowd corpus, smart filtering, recommendations, and ratings on posters.</p>
</header>

<section class="card"><h2>Debrid</h2>
  <p class="hint">Which debrid services do you use? Singularity surfaces cache status for these.</p>
  <p class="note">Your debrid <strong>keys live in your VortX account</strong> (end-to-end encrypted) and are used on your device - they are never put in this add-on URL.</p>
  <div class="grid">${checks("debridServices", DEBRID_SERVICES)}</div>
</section>

<section class="card"><h2>Usenet</h2>
  <p class="hint">First-class NZB / Usenet streaming, alongside torrents + debrid.</p>
  <p class="note">Usenet provider keys also live in your VortX account, never in this URL.</p>
  <div class="grid">${checks("usenetServices", USENET_SERVICES)}</div>
</section>

<section class="card"><h2>Your add-ons</h2>
  <p class="hint">Bring your own sources: paste any add-on manifest URLs (one per line). Singularity aggregates them into one ranked, de-duped, filtered list.</p>
  <div class="field"><textarea id="addons" placeholder="https://your-addon.example/manifest.json"></textarea></div>
</section>

<section class="card"><h2>Filters</h2>
  <p class="hint">Trim the firehose before it reaches you.</p>
  <div class="field"><span class="lbl">Resolutions (none = all)</span><div class="chips">${resChips}</div></div>
  <div class="row">
    <div class="field"><label class="lbl" for="minSeeders">Min seeders</label><input id="minSeeders" type="number" min="0" value="0"></div>
    <div class="field"><label class="lbl" for="maxSizeGB">Max size (GB)</label><input id="maxSizeGB" type="number" min="0" max="200" value="100"></div>
    <div class="field"><label class="lbl" for="excludeRegex">Exclude (regex on filename)</label><input id="excludeRegex" type="text" placeholder="e.g. \\bHDCAM\\b|\\bTS\\b"></div>
  </div>
  <div class="row" style="margin-top:14px">
    <label class="toggle"><input id="hdrOnly" type="checkbox"> HDR / Dolby Vision only</label>
    <label class="toggle"><input id="excludeCam" type="checkbox" checked> Exclude CAM / TS</label>
    <div class="field"><label class="lbl" for="minSourceNodes">Min source nodes (1 = off)</label><input id="minSourceNodes" type="number" min="1" max="10" value="1"></div>
  </div>
</section>

<section class="card"><h2>Quality tags</h2>
  <p class="hint">Fine-grained audio / video / encode control. Include = keep only sources carrying at least one; Exclude = drop any source that has one.</p>
  <div class="field"><span class="lbl">Include (any of)</span><div class="chips">${tagChips("includeTags")}</div></div>
  <div class="field" style="margin-top:14px"><span class="lbl">Exclude</span><div class="chips">${tagChips("excludeTags")}</div></div>
</section>

<section class="card"><h2>Languages</h2>
  <p class="hint">Filter by audio language. Include keeps your languages (sources with no language tag stay visible); Exclude drops anything in that language.</p>
  <div class="field"><span class="lbl">Include (any of)</span><div class="chips">${langChips("includeLanguages")}</div></div>
  <div class="field" style="margin-top:14px"><span class="lbl">Exclude</span><div class="chips">${langChips("excludeLanguages")}</div></div>
</section>

<section class="card"><h2>Source types</h2>
  <p class="hint">Which kinds of source to show. Leave Include empty for all; e.g. exclude Usenet if you have no provider.</p>
  <div class="field"><span class="lbl">Include (any of)</span><div class="chips">${kindChips("includeKinds")}</div></div>
  <div class="field" style="margin-top:14px"><span class="lbl">Exclude</span><div class="chips">${kindChips("excludeKinds")}</div></div>
</section>

<section class="card"><h2>Sort &amp; format</h2>
  <p class="hint">Rank order (strongest first) and how each result reads.</p>
  <div class="field"><span class="lbl">Sort keys</span><div class="grid">${sortRows}</div></div>
  <div class="row" style="margin-top:14px">
    <div class="field"><label class="lbl" for="format">Result format</label><select id="format">${formatOpts}</select></div>
    <div class="field"><label class="toggle" style="margin-top:24px"><input id="proxyEnabled" type="checkbox"> Route streams through a proxy</label></div>
  </div>
  <div class="field" style="margin-top:14px"><label class="lbl" for="formatTemplate">Custom template (used when format = custom)</label>
    <input id="formatTemplate" type="text" placeholder="{quality} • {size} • {tags}\\n⚡ {cached} • 🌱 {seeders} • {source}">
    <p class="hint" style="margin-top:6px">Variables: ${FORMAT_TEMPLATE_VARS.map((v) => `<code>{${v}}</code>`).join(" ")} - use <code>\\n</code> for a new line. Empty values are trimmed.</p>
  </div>
  <div class="row" style="margin-top:14px">
    <div class="field"><label class="lbl" for="maxResults">Max results total (0 = unlimited)</label><input id="maxResults" type="number" min="0" max="200" value="0"></div>
    <div class="field"><label class="lbl" for="maxPerResolution">Max per resolution (0 = unlimited)</label><input id="maxPerResolution" type="number" min="0" max="50" value="0"></div>
  </div>
  <div class="row" style="margin-top:14px">
    <label class="toggle"><input id="dedup" type="checkbox"> Collapse duplicate releases (keep the healthiest)</label>
  </div>
</section>

<section class="card"><h2>Preferred order</h2>
  <p class="hint">Soft ranking: matching sources float to the top WITHOUT hiding anything else (e.g. prefer your languages, or HDR over SDR). Takes effect only when "preferred" is one of your sort keys above.</p>
  <div class="field"><span class="lbl">Preferred resolutions</span><div class="chips">${resChipsFor("preferredResolutions")}</div></div>
  <div class="field" style="margin-top:14px"><span class="lbl">Preferred languages</span><div class="chips">${langChips("preferredLanguages")}</div></div>
  <div class="field" style="margin-top:14px"><span class="lbl">Preferred tags</span><div class="chips">${tagChips("preferredTags")}</div></div>
</section>

<section class="card"><h2>Ratings on posters</h2>
  <p class="hint">Bake IMDb / Rotten Tomatoes / TMDB ratings + quality badges onto poster art.</p>
  <label class="toggle"><input id="ratingsEnabled" type="checkbox"> Enable poster ratings</label>
  <div class="field"><label class="lbl" for="ratingsInstance">Ratings service URL</label><input id="ratingsInstance" type="text" placeholder="https://your-ratings.example"></div>
</section>

<section class="card"><h2>Recommendations</h2>
  <p class="hint">Personalized "Top Picks for You" and "Because You Watched" rows from your taste profile.</p>
  <label class="toggle"><input id="recsEnabled" type="checkbox"> Enable recommendation catalogs</label>
  <div class="field"><label class="lbl" for="historySource">History source</label><select id="historySource">${historyOpts}</select></div>
</section>
</div>

<div class="footer"><div class="inner">
  <div class="url" id="manifestUrl">${baseUrl}/manifest.json</div>
  <button class="btn-ghost" id="copyBtn">Copy URL</button>
  <button class="btn-primary" id="installBtn">Install in VortX</button>
</div></div>

<script>
  const BASE = ${JSON.stringify(baseUrl)};
  const vals = (g) => [...document.querySelectorAll('[data-group="'+g+'"]:checked')].map(e=>e.value);
  function buildConfig(){
    return {
      debridServices: vals('debridServices'), usenetServices: vals('usenetServices'),
      addons: document.getElementById('addons').value.split('\\n').map(s=>s.trim()).filter(Boolean).slice(0,50),
      filters: {
        resolutions: vals('resolutions'),
        excludeRegex: document.getElementById('excludeRegex').value.slice(0,256),
        minSeeders: Math.max(0, parseInt(document.getElementById('minSeeders').value||'0',10)||0),
        maxSizeGB: Math.min(200, Math.max(0, parseInt(document.getElementById('maxSizeGB').value||'100',10)||100)),
        hdrOnly: document.getElementById('hdrOnly').checked, excludeCam: document.getElementById('excludeCam').checked,
        includeTags: vals('includeTags'), excludeTags: vals('excludeTags'),
        includeLanguages: vals('includeLanguages'), excludeLanguages: vals('excludeLanguages'),
        minSourceNodes: Math.min(10, Math.max(1, parseInt(document.getElementById('minSourceNodes').value||'1',10)||1)),
        includeKinds: vals('includeKinds'), excludeKinds: vals('excludeKinds'),
        preferredResolutions: vals('preferredResolutions'), preferredLanguages: vals('preferredLanguages'), preferredTags: vals('preferredTags'),
        maxResults: Math.min(200, Math.max(0, parseInt(document.getElementById('maxResults').value||'0',10)||0)),
        maxPerResolution: Math.min(50, Math.max(0, parseInt(document.getElementById('maxPerResolution').value||'0',10)||0)),
        dedup: document.getElementById('dedup').checked,
      },
      sort: vals('sort'),
      format: document.getElementById('format').value,
      formatTemplate: document.getElementById('formatTemplate').value.slice(0,240),
      proxyEnabled: document.getElementById('proxyEnabled').checked,
      ratings: { enabled: document.getElementById('ratingsEnabled').checked, instance: document.getElementById('ratingsInstance').value },
      recommendations: { enabled: document.getElementById('recsEnabled').checked, historySource: document.getElementById('historySource').value },
    };
  }
  function b64url(s){ return btoa(unescape(encodeURIComponent(s))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,''); }
  function manifestUrl(){ return BASE + '/' + b64url(JSON.stringify(buildConfig())) + '/manifest.json'; }
  function refresh(){ document.getElementById('manifestUrl').textContent = manifestUrl(); }
  document.addEventListener('input', refresh); document.addEventListener('change', refresh);
  document.getElementById('copyBtn').onclick = async () => { try{ await navigator.clipboard.writeText(manifestUrl()); }catch(e){} };
  document.getElementById('installBtn').onclick = () => { location.href = manifestUrl().replace(/^https?:/, 'stremio:'); };
  refresh();
</script>
</body></html>`;
}
