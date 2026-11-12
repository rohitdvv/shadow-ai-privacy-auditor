/**
 * Rule-based named-entity recognition for people and organisations.
 *
 * Statistical NER models are large and slow to ship into a browser extension,
 * so this is a deterministic, explainable substitute: capitalisation shape +
 * a given-name gazetteer + honorifics + a role-cue window, with an aggressive
 * stop-list whose whole job is to prevent over-redaction.
 *
 * Every decision is recorded in `signals` so the UI can explain *why* something
 * was flagged as a name.
 */

import { CATEGORIES as C, SEVERITY as S } from './constants.js';
import { GIVEN_NAMES, HONORIFICS, NAME_STOPWORDS, PERSON_CONTEXT_CUES, ORG_SUFFIXES } from './gazetteers.js';

const lc = (s) => s.toLowerCase().replace(/[.'’]+$/, '');
const setOf = (arr) => new Set(arr);

/** Extra capitalised vocabulary that is never a person's name. */
const NON_NAME_WORDS = setOf([
  // roles & disciplines
  'engineer','engineering','developer','development','analyst','analytics','designer','design','scientist',
  'science','architect','manager','management','director','officer','coordinator','specialist','consultant',
  'administrator','executive','president','founder','partner','associate','assistant','intern','apprentice',
  'machine','learning','artificial','intelligence','data','cloud','security','software','hardware','product',
  'marketing','sales','finance','financial','operations','legal','compliance','support','research','strategy',
  'business','service','services','solution','solutions','system','systems','platform','network','mobile',
  'web','digital','global','national','international','regional','local','annual','quarterly','monthly',
  'weekly','daily','human','resources','payroll','recruitment','talent','training','onboarding','safeguarding',
  'volunteer','volunteers','donor','donors','beneficiary','beneficiaries','community','outreach','programme',
  'chief','senior','junior','lead','principal','staff','head','deputy','vice','acting','interim',
  // document & meeting vocabulary
  'agenda','minutes','memo','memorandum','proposal','contract','agreement','invoice','receipt','statement',
  'policy','procedure','handbook','guideline','guidelines','checklist','template','framework','standard',
  'dashboard','metrics','kpi','okr','roadmap','backlog','retrospective','postmortem','onepager','brief',
  // generic nouns that get title-cased in headings
  'overview','introduction','background','objective','objectives','scope','approach','methodology','results',
  'findings','conclusion','recommendation','recommendations','appendix','reference','references','glossary',
  'risk','risks','issue','issues','action','actions','decision','decisions','next','steps','owner','status',
  'phase','stage','sprint','iteration','release','version','build','environment','production','staging',
  // product, interface and engineering vocabulary that is routinely title-cased
  'settings','page','pages','save','changes','change','log','pull','request','requests','merge','commit',
  'server','client','gateway','payment','payments','checkout','button','menu','tab','panel','dialog','modal',
  'form','field','table','column','row','index','query','database','cache','queue','worker','runner','job',
  'pipeline','workflow','action','deploy','deployment','docker','compose','express','http','https','api',
  'app','application','router','component','module','class','function','method','service','controller',
  'series','round','seed','review','reviews','score','promoter','net','gross','margin','order','quantity',
  'terms','privacy','source','open','time','black','golden','gate','bridge','pro','air','mini','max','plus',
  'studio','code','visual','null','pointer','error','exception','test','tests','user','users','admin',
  'address','speech','act','award','prize','cup','league','university','college','school','hospital',
  'mode','strict','safe','dark','light','debug','demo','day','board','team','list','load','more',
  // frequently capitalised misc
  'internet','email','online','offline','remote','hybrid','office','headquarters','campus','building','room',
  'north','south','east','west','street','avenue','road','city','town','county','state','province','country',
]);

/** Place names that should be classed as locations, not people. */
const PLACE_NAMES = setOf([
  'america','american','africa','asia','europe','australia','canada','mexico','brazil','india','china','japan',
  'korea','germany','france','spain','italy','portugal','netherlands','belgium','sweden','norway','denmark',
  'finland','poland','ireland','scotland','wales','england','britain','kingdom','states','emirates','zealand',
  'york','london','paris','berlin','madrid','rome','tokyo','beijing','shanghai','mumbai','delhi','bangalore',
  'sydney','melbourne','toronto','vancouver','chicago','boston','seattle','austin','denver','atlanta','miami',
  'houston','dallas','phoenix','portland','francisco','angeles','diego','jose','antonio','vegas','orleans',
  'washington','oregon','california','texas','florida','virginia','carolina','dakota','jersey','hampshire',
  'mexico','island','georgia','montana','nevada','arizona','colorado','oklahoma','kansas','iowa','ohio',
  'michigan','illinois','indiana','kentucky','tennessee','alabama','louisiana','arkansas','missouri','utah',
  'idaho','wyoming','nebraska','minnesota','wisconsin','maine','vermont','maryland','delaware','pennsylvania',
  'nairobi','lagos','cairo','johannesburg','dubai','singapore','manila','jakarta','bangkok','hanoi','dhaka',
]);

/**
 * Imperatives and greetings that open a prompt right before a name — "Email
 * John Carter", "Dear Priya Shah". They are trimmed off the front of a run, not
 * used to reject it, so the name is still caught but redaction no longer eats
 * the user's verb. None of these collide with the given-name gazetteer.
 */
const LEADING_NON_NAME = setOf([
  'email','call','ask','tell','text','message','ping','contact','invite','remind','reply','forward','notify',
  'send','write','draft','compose','cc','bcc','dm','thank','thanks','dear','hi','hello','hey','please',
  'introduce','meet','welcome','congratulate','schedule','book','summarize','summarise','explain',
  'translate','rewrite','help','fix','check','find',
]);

/** Particles that can sit inside a multi-part surname. */
const NAME_PARTICLES = setOf(['van','von','de','del','della','di','da','du','la','le','bin','binti','al','el','ibn','ter','ten','dos','das','af','av','mac','mc',"o'"]);

function tokenize(text) {
  const tokens = [];
  const re = /[A-Za-zÀ-ÖØ-öø-ÿ][A-Za-zÀ-ÖØ-öø-ÿ'’]*\.?/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    const raw = m[0];
    tokens.push({
      raw,
      lower: lc(raw),
      start: m.index,
      end: m.index + raw.length,
      cap: /^[A-ZÀ-Ö]/.test(raw),
      allCaps: /^[A-ZÀ-Ö.]+$/.test(raw) && raw.replace(/\./g, '').length > 1,
    });
  }
  return tokens;
}

/** True when the token begins a sentence (so its capital letter carries no information). */
function isSentenceInitial(text, token) {
  let i = token.start - 1;
  while (i >= 0 && /[\s"'“‘(\[]/.test(text[i])) i--;
  if (i < 0) return true;
  return /[.!?:;•\-–—\n]/.test(text[i]);
}

function contextWindow(text, start, end, radius = 60) {
  return text.slice(Math.max(0, start - radius), Math.min(text.length, end + radius)).toLowerCase();
}

/** Possessives sit near almost anything ("my React component"), so they only support a known first name. */
const WEAK_PERSON_CUES = setOf(['my', 'our', 'his', 'her', 'their']);

function hasPersonCue(text, start, end, strongOnly = false) {
  const before = text.slice(Math.max(0, start - 45), start).toLowerCase();
  const after = text.slice(end, Math.min(text.length, end + 35)).toLowerCase();
  const window = before + ' \u0000 ' + after;
  return PERSON_CONTEXT_CUES.some((cue) => {
    if (strongOnly && WEAK_PERSON_CUES.has(cue)) return false;
    if (cue.includes(' ')) return window.includes(cue);
    return new RegExp(`\\b${cue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`).test(window);
  });
}

/**
 * Extract person/organisation candidates.
 * @returns {Array} raw findings (pre-context-scoring)
 */
export function extractEntities(text) {
  const tokens = tokenize(text);
  const out = [];
  let i = 0;

  while (i < tokens.length) {
    if (!tokens[i].cap) { i++; continue; }

    // Grow a maximal run of capitalised tokens (particles allowed in the middle).
    let j = i;
    while (j + 1 < tokens.length) {
      // A full stop ends the sentence, and a name never spans two sentences:
      // "…the Pull Request. Ask John Carter" is not one five-word name. Initials
      // ("J.") and titles ("Dr.") keep their full stop and carry on.
      const cur = tokens[j];
      if (cur.raw.endsWith('.') && cur.lower.length > 1 && !HONORIFICS.has(cur.lower)) break;
      const gap = text.slice(tokens[j].end, tokens[j + 1].start);
      if (!/^[ \t]*[-'’]?[ \t]*$/.test(gap) || gap.length > 2) break;
      const next = tokens[j + 1];
      const isParticle = NAME_PARTICLES.has(next.lower) && j + 2 < tokens.length && tokens[j + 2].cap;
      if (!next.cap && !isParticle) break;
      j++;
      if (j - i >= 4) break;
    }

    let run = tokens.slice(i, j + 1);
    while (run.length > 1 && LEADING_NON_NAME.has(run[0].lower)) run = run.slice(1);
    const start = run[0].start;
    // The tokenizer keeps a trailing full stop for initials ("J.") and titles.
    // On a longer last word it is the end of the sentence, not part of the name.
    const last = run[run.length - 1];
    const end = last.raw.endsWith('.') && last.raw.length > 2 ? last.end - 1 : last.end;
    const value = text.slice(start, end);
    const words = run.map((t) => t.lower);

    const result = classifyRun({ text, run, words, value, start, end });
    if (result) out.push(result);

    i = j + 1;
  }

  return out;
}

function classifyRun({ text, run, words, value, start, end }) {
  const signals = [];

  // --- hard rejections -------------------------------------------------
  if (words.every((w) => NAME_STOPWORDS.has(w) || NON_NAME_WORDS.has(w))) return null;
  if (words.every((w) => PLACE_NAMES.has(w))) return null;
  if (run.every((t) => t.allCaps) && !words.some((w) => GIVEN_NAMES.has(w))) return null; // acronyms
  if (value.length < 3) return null;
  // "Big O", "Plan B", "Series A": a bare single letter is a label, not a surname (an initial is "J.").
  if (run.some((t) => t.raw.length === 1) && !words.some((w) => GIVEN_NAMES.has(w))) return null;

  const prevWord = previousWord(text, start);
  // The title can sit just before the run ("Dr Okafor" after a lower-case word) or open it ("Mr. Okafor").
  const hasHonorific = Boolean(prevWord && HONORIFICS.has(lc(prevWord))) || (words.length > 1 && HONORIFICS.has(words[0]));
  const hasGazetteerHit = words.some((w) => GIVEN_NAMES.has(w));
  // "Roth IRA", "Project ALPHA", "Amazon AWS" — an embedded acronym means this is a
  // term of art, not a person, unless a first name or honorific says otherwise.
  if (run.some((t) => t.allCaps) && !hasGazetteerHit && !hasHonorific) return null;

  // "Project Halberd", "Team Atlas", "Room Nightingale" — a leading common noun
  // makes this a label for a thing, not a person. Those belong to other rules.
  const firstWord = words[0];
  if ((NAME_STOPWORDS.has(firstWord) || NON_NAME_WORDS.has(firstWord)) && !hasGazetteerHit && !hasHonorific) return null;

  // Organisation? (ends with a corporate suffix)
  const lastWord = words[words.length - 1];
  if (ORG_SUFFIXES.has(lastWord) && run.length >= 2) {
    const ctx = contextWindow(text, start, end, 90);
    const orgSensitive = /\b(?:client|customer|account|vendor|supplier|partner|acquire|acquisition|merger|contract|nda|confidential|deal|donor|grantee|beneficiary)\b/.test(ctx);
    if (!orgSensitive) return null;
    return {
      ruleId: 'ner_organisation',
      category: C.ORG,
      severity: S.MEDIUM,
      label: 'ORGANIZATION',
      title: 'Named organisation in a confidential context',
      why: 'Naming the other party turns a generic question into a disclosure of who you do business with, which is normally covered by a confidentiality clause.',
      value, start, end,
      confidence: 0.62,
      signals: ['corporate suffix', 'confidential business context'],
    };
  }

  // --- scoring ---------------------------------------------------------
  const prevToken = prevWord;
  const honorific = hasHonorific;
  const gazetteerHit = hasGazetteerHit;
  const cue = hasPersonCue(text, start, end, !hasGazetteerHit && !hasHonorific);
  const sentenceInitial = isSentenceInitial(text, run[0]);
  const multiWord = run.filter((t) => t.cap).length >= 2;
  const containsNonName = words.some((w) => NON_NAME_WORDS.has(w) || PLACE_NAMES.has(w));

  let score = 0;
  if (multiWord) { score += 0.5; signals.push('two or more capitalised words'); }
  if (gazetteerHit) { score += 0.3; signals.push('matches a common given name'); }
  if (honorific) { score += 0.55; signals.push(`preceded by honorific "${prevToken}"`); }
  if (cue) { score += 0.25; signals.push('appears next to a person-role cue'); }
  if (!multiWord && !gazetteerHit && !honorific) return null;
  if (!multiWord && sentenceInitial && !honorific) return null;
  if (sentenceInitial && !gazetteerHit && !honorific && !cue) score -= 0.2;
  if (containsNonName && !gazetteerHit && !honorific) score -= 0.35;
  // Capital letters alone are weak evidence: "Golden Gate Bridge", "Pull Request"
  // and "Save Changes" look exactly like a name. Without a known first name, a
  // title or a person cue, stay below the default reporting threshold.
  if (multiWord && !gazetteerHit && !honorific && !cue) { score -= 0.2; signals.push('capitalisation is the only evidence'); }
  if (/'s$|’s$/.test(value)) score += 0.05;

  // Possessive/plural stripping for the reported value.
  if (score < 0.3) return null;

  const severity = score >= 0.75 ? S.HIGH : S.MEDIUM;

  return {
    ruleId: 'ner_person_name',
    category: C.CONTACT,
    severity,
    label: 'NAME',
    title: 'Person name',
    why: 'A full name is the primary key that links every other detail in your prompt to a real, identifiable individual.',
    value, start, end,
    confidence: Math.min(0.95, score),
    signals,
  };
}

function previousWord(text, start) {
  const before = text.slice(Math.max(0, start - 24), start);
  const m = before.match(/([A-Za-z][A-Za-z.'’]*)[\s.]*$/);
  return m ? m[1] : null;
}
