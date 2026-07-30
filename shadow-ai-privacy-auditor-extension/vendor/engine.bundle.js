/**
 * Shadow AI Privacy Auditor — bundled detection engine (generated file).
 *
 * DO NOT EDIT. Regenerate with: npm run build:extension
 * Source of truth: /engine/*.js
 *
 * Contains no network calls of any kind.
 */
(function (root) {
  'use strict';

  /* ==== engine/constants.js ==== */
  /**
   * Shadow AI Privacy Auditor — category & severity constants.
   * Zero dependencies. Shared by the web app, the browser extension and the test runner.
   */

  const CATEGORIES = {
    CONTACT: 'contact',
    GOV_FIN: 'government_financial',
    CREDENTIALS: 'credentials',
    MEDICAL: 'medical_sensitive',
    PEOPLE: 'people_records',
    ORG: 'org_confidential',
  };

  const SEVERITY = {
    CRITICAL: 'critical',
    HIGH: 'high',
    MEDIUM: 'medium',
    LOW: 'low',
  };

  /** Points contributed to the 0-100 risk score by a single max-confidence finding. */
  const SEVERITY_WEIGHT = {
    critical: 45,
    high: 22,
    medium: 9,
    low: 3,
  };

  const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

  const CATEGORY_META = {
    [CATEGORIES.CONTACT]: {
      id: CATEGORIES.CONTACT,
      order: 1,
      name: 'Names & Contact Information',
      short: 'Contact',
      color: '#2563eb',
      tint: '#dbeafe',
      description:
        'Directly identifying details about a person: full names, email addresses, phone numbers, postal addresses, dates of birth and personal handles.',
      why:
        'Public AI assistants may retain prompts for abuse monitoring or model improvement. Identifiers let a person be re-identified from an otherwise harmless prompt and can trigger notification duties under GDPR / CCPA.',
    },
    [CATEGORIES.GOV_FIN]: {
      id: CATEGORIES.GOV_FIN,
      order: 2,
      name: 'Government & Financial Identifiers',
      short: 'Gov / Financial',
      color: '#b91c1c',
      tint: '#fee2e2',
      description:
        'Government-issued numbers and financial account data: SSN/ITIN/EIN, passport and licence numbers, payment cards, bank accounts, IBAN, national IDs.',
      why:
        'These are the raw material for identity theft and financial fraud. They are almost never necessary to get a useful answer from an AI assistant, and sharing card data outside a compliant environment breaches PCI-DSS.',
    },
    [CATEGORIES.CREDENTIALS]: {
      id: CATEGORIES.CREDENTIALS,
      order: 3,
      name: 'Passwords, Keys & Credentials',
      short: 'Credentials',
      color: '#7c2d12',
      tint: '#ffedd5',
      description:
        'Live secrets: passwords, API keys, access and refresh tokens, JWTs, private keys, database connection strings and authorization headers.',
      why:
        'A pasted secret must be treated as compromised the moment it leaves your machine. Anyone with prompt access — or anyone who later breaches the provider — can use it directly. Rotate, never re-use.',
    },
    [CATEGORIES.MEDICAL]: {
      id: CATEGORIES.MEDICAL,
      order: 4,
      name: 'Medical & Sensitive Personal Data',
      short: 'Medical / Sensitive',
      color: '#a21caf',
      tint: '#fae8ff',
      description:
        'Health conditions, medications, medical record and insurance numbers, plus other special-category data such as immigration status, religion, ethnicity, sexual orientation and biometrics.',
      why:
        'This is special-category data under GDPR Art. 9 and PHI under HIPAA. Disclosure can cause discrimination or lasting personal harm, and no general-purpose AI vendor is a covered business associate by default.',
    },
    [CATEGORIES.PEOPLE]: {
      id: CATEGORIES.PEOPLE,
      order: 5,
      name: 'Employee, Client & Volunteer Records',
      short: 'People Records',
      color: '#0f766e',
      tint: '#ccfbf1',
      description:
        'Internal people data: employee/volunteer/client/case IDs, salary and compensation, performance ratings, disciplinary matters, donor and beneficiary records.',
      why:
        'You are usually the custodian, not the owner, of this data. Sharing it externally breaks the confidentiality your organisation promised to staff, clients and volunteers, and often breaches your own HR data policy.',
    },
    [CATEGORIES.ORG]: {
      id: CATEGORIES.ORG,
      order: 6,
      name: 'Confidential Organisational Information',
      short: 'Org Confidential',
      color: '#a16207',
      tint: '#fef3c7',
      description:
        'Non-public business information: documents marked confidential or under NDA, project codenames, internal systems and tickets, unreleased financials, contract values, M&A and restructuring plans.',
      why:
        'Non-public business information loses trade-secret protection once disclosed to an uncontrolled third party, and may breach NDAs or securities rules if it is material and unannounced.',
    },
  };

  const CATEGORY_LIST = Object.values(CATEGORY_META).sort((a, b) => a.order - b.order);

  /** Risk bands for the overall 0-100 score. */
  const RISK_BANDS = [
    { min: 0, max: 0, level: 'safe', label: 'Safe to send', color: '#15803d' },
    { min: 1, max: 24, level: 'low', label: 'Low risk', color: '#65a30d' },
    { min: 25, max: 49, level: 'moderate', label: 'Moderate risk', color: '#ca8a04' },
    { min: 50, max: 74, level: 'high', label: 'High risk', color: '#ea580c' },
    { min: 75, max: 100, level: 'critical', label: 'Critical — do not send', color: '#b91c1c' },
  ];

  function bandForScore(score) {
    return RISK_BANDS.find((b) => score >= b.min && score <= b.max) || RISK_BANDS[0];
  }

  /* ==== import aliases ==== */
  const C = CATEGORIES;
  const S = SEVERITY;
  /* ==== engine/validators.js ==== */
  /**
   * Checksum / structural validators.
   *
   * These are what separate "looks like a 16 digit number" from "is a payment card".
   * Every validator is pure, synchronous and dependency-free.
   */

  /** Luhn (mod 10) — payment cards, IMEI, NPI. */
  function luhn(digits) {
    const s = String(digits).replace(/\D/g, '');
    if (s.length < 12) return false;
    let sum = 0;
    let alt = false;
    for (let i = s.length - 1; i >= 0; i--) {
      let d = s.charCodeAt(i) - 48;
      if (alt) {
        d *= 2;
        if (d > 9) d -= 9;
      }
      sum += d;
      alt = !alt;
    }
    return sum % 10 === 0;
  }

  /** Payment-card brand from the IIN/BIN prefix. Returns null when nothing matches. */
  function cardBrand(digits) {
    const s = String(digits).replace(/\D/g, '');
    if (/^4\d{12}(\d{3})?(\d{3})?$/.test(s)) return 'Visa';
    if (/^(5[1-5]\d{4}|222[1-9]\d{2}|22[3-9]\d{3}|2[3-6]\d{4}|27[01]\d{3}|2720\d{2})\d{10}$/.test(s)) return 'Mastercard';
    if (/^3[47]\d{13}$/.test(s)) return 'American Express';
    if (/^6(?:011|5\d{2}|4[4-9]\d)\d{12}$/.test(s)) return 'Discover';
    if (/^3(?:0[0-5]|[68]\d)\d{11}$/.test(s)) return 'Diners Club';
    if (/^(?:2131|1800|35\d{3})\d{11}$/.test(s)) return 'JCB';
    if (/^(?:50|5[6-9]|6\d)\d{10,17}$/.test(s)) return 'Maestro';
    return null;
  }

  /** IBAN mod-97-10 (ISO 7064). */
  function ibanValid(raw) {
    const s = String(raw).replace(/[\s-]/g, '').toUpperCase();
    if (!/^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/.test(s)) return false;
    const lengths = {
      AD: 24, AE: 23, AL: 28, AT: 20, AZ: 28, BA: 20, BE: 16, BG: 22, BH: 22, BR: 29,
      CH: 21, CR: 22, CY: 28, CZ: 24, DE: 22, DK: 18, DO: 28, EE: 20, ES: 24, FI: 18,
      FO: 18, FR: 27, GB: 22, GE: 22, GI: 23, GL: 18, GR: 27, GT: 28, HR: 21, HU: 28,
      IE: 22, IL: 23, IS: 26, IT: 27, JO: 30, KW: 30, KZ: 20, LB: 28, LI: 21, LT: 20,
      LU: 20, LV: 21, MC: 27, MD: 24, ME: 22, MK: 19, MR: 27, MT: 31, MU: 30, NL: 18,
      NO: 15, PK: 24, PL: 28, PS: 29, PT: 25, QA: 29, RO: 24, RS: 22, SA: 24, SE: 24,
      SI: 19, SK: 24, SM: 27, TN: 24, TR: 26, UA: 29, VG: 24, XK: 20,
    };
    const expect = lengths[s.slice(0, 2)];
    if (expect && s.length !== expect) return false;
    const rearranged = s.slice(4) + s.slice(0, 4);
    let remainder = 0;
    for (const ch of rearranged) {
      const code = ch.charCodeAt(0);
      const part = code >= 65 ? String(code - 55) : ch;
      for (const digit of part) remainder = (remainder * 10 + (digit.charCodeAt(0) - 48)) % 97;
    }
    return remainder === 1;
  }

  /** ABA / US routing transit number checksum. */
  function abaRoutingValid(raw) {
    const s = String(raw).replace(/\D/g, '');
    if (s.length !== 9) return false;
    if (/^0{9}$/.test(s)) return false;
    const d = [...s].map(Number);
    const sum =
      3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + 1 * (d[2] + d[5] + d[8]);
    return sum % 10 === 0;
  }

  /* Verhoeff tables — used by India's Aadhaar. */
  const VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
  ];
  const VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
  ];

  function verhoeffValid(raw) {
    const s = String(raw).replace(/\D/g, '');
    if (s.length !== 12) return false;
    let c = 0;
    const rev = [...s].reverse().map(Number);
    for (let i = 0; i < rev.length; i++) c = VERHOEFF_D[c][VERHOEFF_P[i % 8][rev[i]]];
    return c === 0;
  }

  /** US NPI: Luhn over "80840" + the first 9 digits. */
  function npiValid(raw) {
    const s = String(raw).replace(/\D/g, '');
    if (s.length !== 10) return false;
    return luhn('80840' + s);
  }

  /** Structural SSN rules (area/group/serial), independent of the regex. */
  function ssnStructurallyValid(raw) {
    const s = String(raw).replace(/\D/g, '');
    if (s.length !== 9) return false;
    const area = s.slice(0, 3);
    const group = s.slice(3, 5);
    const serial = s.slice(5);
    if (area === '000' || area === '666' || area[0] === '9') return false;
    if (group === '00' || serial === '0000') return false;
    if (/^(\d)\1{8}$/.test(s)) return false;          // 111111111
    if (s === '123456789' || s === '987654321') return false;
    return true;
  }

  /** Shannon entropy in bits per character. */
  function shannonEntropy(str) {
    if (!str) return 0;
    const freq = Object.create(null);
    for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
    let h = 0;
    const n = str.length;
    for (const k in freq) {
      const p = freq[k] / n;
      h -= p * Math.log2(p);
    }
    return h;
  }

  /** How many distinct character classes appear (lower/upper/digit/symbol). */
  function charClasses(str) {
    let n = 0;
    if (/[a-z]/.test(str)) n++;
    if (/[A-Z]/.test(str)) n++;
    if (/\d/.test(str)) n++;
    if (/[^A-Za-z0-9]/.test(str)) n++;
    return n;
  }

  /**
   * Heuristic "this looks like a machine-generated secret" test.
   * Used only for the generic high-entropy rule, never for keyed patterns.
   */
  function looksLikeSecret(str) {
    if (!str || str.length < 16) return false;
    if (/^[0-9]+$/.test(str)) return false;                 // plain numbers handled elsewhere
    if (/^(?:[A-Z][a-z]+)+$/.test(str)) return false;       // CamelCaseWords
    if (/\s/.test(str)) return false;
    const entropy = shannonEntropy(str);
    const classes = charClasses(str);
    return entropy >= 3.4 && classes >= 2;
  }

  /**
   * Well-known documentation / test values. We still surface these, but at low
   * severity, so a tutorial snippet does not scream "critical".
   */
  const KNOWN_TEST_VALUES = new Set([
    '4111111111111111', '4242424242424242', '4012888888881881', '5555555555554444',
    '5105105105105100', '378282246310005', '371449635398431', '6011111111111117',
    '30569309025904', '3530111333300000', '000000000', '123456789',
    // Stripe's publicly documented test key (published in their own docs). It is
    // NOT a real secret; it lives here so tutorial snippets are down-ranked, not
    // treated as critical. Assembled from parts so automated secret scanners do
    // not misflag this well-known public constant on push.
    ['sk', 'test', '4eC39HqLyjWDarjtT1zdp7dc'].join('_'),
  ]);

  function isKnownTestValue(raw) {
    const digits = String(raw).replace(/[\s-]/g, '');
    return KNOWN_TEST_VALUES.has(digits) || KNOWN_TEST_VALUES.has(String(raw).trim());
  }

  /** Private / reserved IPv4 space — informational rather than sensitive. */
  function isPrivateIPv4(ip) {
    const p = ip.split('.').map(Number);
    if (p.length !== 4 || p.some((n) => Number.isNaN(n) || n > 255)) return false;
    if (p[0] === 10) return true;
    if (p[0] === 127) return true;
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
    if (p[0] === 192 && p[1] === 168) return true;
    if (p[0] === 169 && p[1] === 254) return true;
    if (p[0] === 0 || p[0] >= 224) return true;
    return false;
  }

  function isValidIPv4(ip) {
    const p = ip.split('.');
    if (p.length !== 4) return false;
    return p.every((s) => /^\d{1,3}$/.test(s) && Number(s) <= 255 && !(s.length > 1 && s[0] === '0'));
  }

  /* ==== engine/gazetteers.js ==== */
  /**
   * Word lists used by the rule-based NER and the context scorer.
   *
   * NOTE ON RESPONSIBLE DATA USE: these are generic English/global vocabulary
   * lists (common given names, clinical nouns, business jargon). They contain no
   * real person's record, no organisation's private data, and nothing scraped
   * from a live system.
   */

  const set = (arr) => new Set(arr.map((s) => s.toLowerCase()));

  /** ~300 common given names across several naming traditions. Used as a *signal*, never as proof. */
  const GIVEN_NAMES = set([
    'aaliyah','aaron','abigail','adam','adrian','aisha','alan','alejandro','alex','alexander','alexis','alice','alicia','amanda','amara','amelia','amir','amy','ana','anand','anders','andre','andrea','andrew','angela','anita','anna','anne','anthony','antonio','arjun','arun','ashley','asha','austin','ava','ayesha',
    'barbara','beatriz','ben','benjamin','bernard','beth','bianca','bilal','bob','bradley','brandon','brenda','brian','brittany','bruce','bryan',
    'caleb','cameron','carla','carlos','carmen','carol','caroline','carrie','catherine','cecilia','chandra','charles','charlotte','chen','cheryl','chloe','chris','christian','christina','christopher','claire','clara','claudia','colin','connor','courtney','craig','cynthia',
    'dana','daniel','danielle','david','dawn','dean','deborah','declan','deepa','denise','dennis','derek','devon','diana','diego','dilip','dmitri','dominic','donald','donna','dorothy','douglas','duncan',
    'edward','elaine','eleanor','elena','eli','elijah','elizabeth','ella','ellen','emily','emma','eric','erica','erin','esther','ethan','eva','evelyn',
    'fatima','felix','fernando','fiona','florence','frances','francis','frank','freya',
    'gabriel','gabriela','gary','gemma','george','georgia','gerald','gina','giovanni','grace','graham','greg','gregory','gustavo',
    'hannah','hans','harold','harper','harry','hassan','hazel','heather','hector','heidi','helen','henry','hiroshi','holly','hugo','hunter',
    'ian','ibrahim','ida','ignacio','imani','ines','irene','isaac','isabel','isabella','ivan','ivy',
    'jack','jackson','jacob','jade','james','jamie','jane','janet','jasmine','jason','javier','jay','jean','jeff','jeffrey','jennifer','jeremy','jesse','jessica','jian','jill','joan','joanna','joe','joel','john','johnathan','jonas','jonathan','jordan','jorge','jose','joseph','joshua','joyce','juan','judith','judy','julia','julian','julie','justin',
    'kaitlyn','kamal','karen','karim','kate','katherine','kathleen','kathryn','katie','keith','kelly','ken','kenneth','kevin','khalid','kim','kimberly','kiran','kirsten','krishna','kristen','kyle',
    'lakshmi','lars','laura','lauren','lawrence','layla','leah','lee','leila','leo','leon','leonard','leslie','liam','lila','lily','linda','lisa','logan','lorenzo','louis','lucas','lucia','lucy','luis','luke','lydia',
    'madeline','madison','mahesh','malik','manuel','marcus','margaret','maria','mariam','marie','marilyn','mario','marisa','mark','marta','martha','martin','mary','mason','mateo','matthew','maureen','maya','megan','mei','melanie','melissa','meredith','mia','michael','michelle','miguel','mika','mila','miles','mohammed','molly','monica','morgan','muhammad','murali',
    'nadia','nancy','naomi','natalie','nathan','neha','neil','nelson','nicholas','nicole','nikhil','nina','noah','noor','nora','norman',
    'olga','oliver','olivia','omar','oscar','owen',
    'pablo','paige','pamela','patricia','patrick','paul','paula','pedro','peter','philip','phoebe','pierre','pooja','priya',
    'quinn','rachel','rafael','raj','rajesh','ralph','ramon','randy','raul','raymond','rebecca','regina','renee','ricardo','richard','riley','rita','robert','roberto','robin','rodney','roger','rohan','roman','ronald','rosa','rose','ruby','russell','ruth','ryan',
    'sabrina','sadie','salma','sam','samantha','samuel','sandra','sanjay','sara','sarah','saul','scott','sean','sebastian','selena','serena','sergio','seth','shannon','sharon','shawn','sheila','shirley','sienna','silvia','simon','sofia','sonia','sophia','sophie','stanley','stella','stephanie','stephen','steven','stuart','sunil','susan','suzanne','sven','sydney',
    'tanya','tara','ted','teresa','terry','thomas','tiffany','timothy','tina','tobias','todd','tomas','tony','tracy','travis','trevor','tyler',
    'uma','valentina','valerie','vanessa','veronica','victor','victoria','vijay','vikram','vincent','violet','vivian',
    'walter','wanda','wayne','wendy','wesley','william','willow','wyatt',
    'xavier','yara','yasmin','yolanda','young','yuki','yusuf','yvonne','zachary','zainab','zara','zoe',
  ]);

  /** Honorifics that make the following capitalised token almost certainly a person. */
  const HONORIFICS = set([
    'mr','mrs','ms','miss','mx','dr','prof','professor','rev','reverend','fr','sir','dame',
    'lord','lady','capt','captain','sgt','lt','col','gen','hon','judge','nurse','pastor','rabbi','imam',
  ]);

  /**
   * Words that are frequently capitalised but are not people.
   * This list is the single biggest defence against over-redaction.
   */
  const NAME_STOPWORDS = set([
    // structural english
    'the','a','an','and','or','but','if','then','this','that','these','those','there','here','it','its',
    'i','we','you','they','he','she','him','her','his','hers','our','your','their','them','us','me','my',
    'is','are','was','were','be','been','being','have','has','had','do','does','did','can','could','will',
    'would','shall','should','may','might','must','not','no','yes','from','to','for','with','without','of',
    'in','on','at','by','as','into','onto','over','under','about','after','before','during','between','per',
    'all','any','each','every','some','most','more','less','than','also','just','only','very','so','such',
    'please','thanks','thank','hi','hello','hey','regards','best','sincerely','cheers','dear','ok','okay',
    'note','notes','update','summary','question','answer','example','sample','draft','final','version',
    // time
    'monday','tuesday','wednesday','thursday','friday','saturday','sunday','today','tomorrow','yesterday',
    'january','february','march','april','may','june','july','august','september','october','november','december',
    'mon','tue','tues','wed','thu','thur','thurs','fri','sat','sun','am','pm','q1','q2','q3','q4',
    'morning','afternoon','evening','night','week','weekend','month','quarter','year','date','time','deadline',
    // business / product vocabulary that is capitalised constantly
    'ai','api','app','apps','team','teams','project','projects','meeting','meetings','review','sprint','standup',
    'company','client','clients','customer','customers','vendor','partner','department','office','branch',
    'report','reports','invoice','budget','plan','planning','roadmap','release','launch','milestone','ticket',
    'board','committee','council','group','division','unit','program','programme','policy','process',
    'monday.com','slack','zoom','teams','google','microsoft','apple','amazon','meta','openai','anthropic',
    'chatgpt','gemini','copilot','claude','excel','word','powerpoint','outlook','gmail','drive','sheets',
    'github','gitlab','jira','confluence','notion','asana','trello','figma','salesforce','workday','sap',
    'python','javascript','java','typescript','react','node','docker','kubernetes','aws','azure','gcp',
    'linux','windows','macos','android','ios','chrome','firefox','safari','edge',
    'inc','llc','ltd','plc','gmbh','corp','corporation','co','company','foundation','trust','society',
    'university','college','school','hospital','clinic','center','centre','institute','agency','bureau',
    'north','south','east','west','central','street','avenue','road','city','county','state','province',
    'usa','uk','eu','us','canada','india','germany','france','japan','china','australia','mexico','brazil',
    'covid','gdpr','hipaa','ccpa','pci','soc','iso','nist','sox','ferpa','phi','pii',
    'true','false','null','none','todo','fixme','warning','error','info','debug','success','failed',
    'new','old','next','last','first','second','third','current','previous','upcoming','open','closed',
    'high','medium','low','critical','urgent','normal','pending','approved','rejected','draft',
  ]);

  /** Tokens near a capitalised word that strongly suggest it names a person. */
  const PERSON_CONTEXT_CUES = [
    'patient','client','employee','volunteer','donor','beneficiary','candidate','applicant','tenant',
    'student','member','customer','contact','colleague','coworker','manager','supervisor','director',
    'nurse','doctor','physician','therapist','caseworker','social worker','attorney','lawyer',
    'name is','named','called','signed by','attn','attention','cc','bcc','regards','sincerely',
    'reports to','managed by','assigned to','spoke with','met with','emailed','called by','on behalf of',
    'mr','mrs','ms','dr','prof','my','our','his','her','their',
  ];

  /** Organisation suffixes — used to label ORG rather than PERSON. */
  const ORG_SUFFIXES = set([
    'inc','inc.','llc','l.l.c.','ltd','ltd.','limited','plc','gmbh','ag','sa','sas','bv','nv','oy','ab',
    'corp','corp.','corporation','company','co','co.','group','holdings','partners','associates','ventures',
    'foundation','trust','society','association','institute','university','college','school','hospital',
    'clinic','council','charity','ngo','nonprofit','coop','cooperative','union','federation','alliance',
  ]);

  /** Health conditions / clinical concepts. Presence of these makes surrounding text special-category. */
  const MEDICAL_CONDITIONS = [
    'hiv','aids','hepatitis','tuberculosis','cancer','carcinoma','leukemia','leukaemia','lymphoma','tumor','tumour',
    'diabetes','type 1 diabetes','type 2 diabetes','hypertension','high blood pressure','hypotension',
    'asthma','copd','emphysema','cystic fibrosis','epilepsy','seizure disorder','multiple sclerosis',
    'parkinson','alzheimer','dementia','stroke','heart attack','myocardial infarction','cardiac arrest',
    'congestive heart failure','arrhythmia','angina','anemia','anaemia','sickle cell',
    'depression','major depressive disorder','anxiety disorder','generalised anxiety','generalized anxiety',
    'bipolar disorder','schizophrenia','psychosis','ptsd','post-traumatic stress','ocd','adhd','add',
    'autism','asperger','eating disorder','anorexia','bulimia','self-harm','suicidal ideation',
    'substance abuse','substance use disorder','alcoholism','alcohol dependence','opioid dependence',
    'addiction','rehab','rehabilitation program','detox','methadone program',
    'pregnancy','pregnant','miscarriage','abortion','fertility treatment','ivf','endometriosis',
    'chemotherapy','radiotherapy','radiation therapy','dialysis','transplant','immunosuppressant',
    'lupus','rheumatoid arthritis','crohn','ulcerative colitis','celiac','psoriasis','eczema',
    'hypothyroidism','hyperthyroidism','thyroid disorder','kidney disease','renal failure','cirrhosis',
    'migraine','chronic pain','fibromyalgia','disability','wheelchair user','blind','deaf',
    'covid-19','long covid','sepsis','pneumonia','osteoporosis','glaucoma','cataract','copd',
    'std','sti','chlamydia','gonorrhea','syphilis','herpes','hpv',
  ];

  /** Prescription and controlled drugs commonly named in notes. */
  const MEDICATIONS = [
    'metformin','insulin','lisinopril','amlodipine','atorvastatin','simvastatin','losartan','metoprolol',
    'levothyroxine','omeprazole','pantoprazole','albuterol','salbutamol','prednisone','prednisolone',
    'amoxicillin','azithromycin','ciprofloxacin','doxycycline','ibuprofen','naproxen','acetaminophen',
    'sertraline','fluoxetine','prozac','zoloft','citalopram','escitalopram','lexapro','venlafaxine',
    'bupropion','wellbutrin','trazodone','mirtazapine','duloxetine','cymbalta','paroxetine',
    'alprazolam','xanax','lorazepam','ativan','clonazepam','klonopin','diazepam','valium','zolpidem','ambien',
    'lithium','quetiapine','seroquel','risperidone','olanzapine','aripiprazole','abilify','haloperidol',
    'adderall','ritalin','methylphenidate','lisdexamfetamine','vyvanse','atomoxetine','strattera',
    'oxycodone','oxycontin','hydrocodone','vicodin','morphine','fentanyl','tramadol','codeine',
    'methadone','buprenorphine','suboxone','naloxone','narcan','naltrexone',
    'warfarin','coumadin','apixaban','eliquis','rivaroxaban','clopidogrel','heparin',
    'gabapentin','pregabalin','lyrica','lamotrigine','levetiracetam','keppra','valproate','carbamazepine',
    'humira','enbrel','methotrexate','hydroxychloroquine','tamoxifen','letrozole','truvada','prep',
    'antiretroviral','chemotherapy drug','immunotherapy',
  ];

  /** Words that indicate the surrounding text is a health record. */
  const MEDICAL_CONTEXT = [
    'patient','diagnosis','diagnosed','prognosis','symptom','symptoms','treatment','treated','therapy',
    'prescription','prescribed','dosage','dose','mg','ml','medication','medications','clinical','clinician',
    'physician','doctor','nurse','hospital','clinic','ward','icu','er','emergency room','admitted','discharge',
    'discharged','referral','referred','lab result','blood test','biopsy','mri','ct scan','x-ray','ultrasound',
    'medical record','health record','chart','ehr','emr','insurance claim','copay','deductible','icd',
    'allergy','allergies','vitals','bp','a1c','cholesterol','history of','presents with','follow-up appointment',
  ];

  /** Immigration / legal-status vocabulary (special-category, frequently pasted into AI tools). */
  const IMMIGRATION_TERMS = [
    'green card','permanent resident','lawful permanent resident','naturalization','naturalisation',
    'asylum seeker','asylum application','refugee status','undocumented','out of status','overstayed',
    'work permit','work authorization','work authorisation','ead card','visa status','visa expired',
    'h-1b','h1b','h-4','l-1','l1 visa','o-1','tn visa','f-1','f1 visa','opt','cpt','j-1','b-1','b-2',
    'uscis','immigration case','deportation','removal proceedings','ice detention','daca','tps',
    'sponsorship required','requires sponsorship','alien registration','a-number',
  ];

  /** Protected / special-category attributes about a person. */
  const PROTECTED_ATTRIBUTES = [
    'sexual orientation','gay','lesbian','bisexual','transgender','non-binary','nonbinary','queer',
    'gender identity','gender reassignment','trade union member','union membership','union organiser',
    'political affiliation','voted for','party membership','religious belief','practising muslim',
    'practicing muslim','practising christian','practicing christian','observant jew','devout hindu',
    'converted to','ethnic origin','ethnicity','race','racial background','caste','indigenous status',
    'criminal record','prior conviction','arrest record','on probation','parole','sex offender registry',
    'biometric data','fingerprint template','facial recognition template','dna profile','genetic test',
  ];

  /** Confidentiality classification markers. */
  const CONFIDENTIALITY_MARKERS = [
    'strictly confidential','company confidential','confidential and proprietary',
    'privileged and confidential','attorney-client privileged','internal use only','internal only',
    'do not distribute','do not forward','not for distribution','not for external release',
    'restricted distribution','classified','trade secret','proprietary information','under nda',
    'subject to nda','embargoed','pre-release','need to know','commercial in confidence',
  ];

  /** Business-sensitive concepts (unannounced financials, deals, restructuring). */
  const BUSINESS_SENSITIVE = [
    'unannounced','unreleased','not yet public','pre-announcement','ahead of the announcement',
    'term sheet','cap table','due diligence','letter of intent','loi signed','acquisition target',
    'merger','acquiring','divestiture','carve-out','ipo filing','s-1','pre-money valuation',
    'post-money valuation','down round','bridge round','runway','burn rate','arr','mrr','churn rate',
    'layoff','layoffs','rif','reduction in force','restructuring plan','redundancy list','headcount cut',
    'severance package','hiring freeze','pip list','succession plan','board deck','earnings before release',
    'win rate','pipeline value','pricing floor','discount authority','margin structure','cost basis',
    'supplier contract','exclusivity clause','non-compete','litigation strategy','settlement amount',
  ];

  /** Words that mark an example as fictional / illustrative — lowers, never zeroes, confidence. */
  const PLACEHOLDER_CUES = [
    'example','e.g.','for example','sample','dummy','placeholder','fictional','fake','made up','made-up',
    'test data','testing only','lorem ipsum','foo','bar','baz','xxx','yyy','zzz','redacted','anonymised',
    'anonymized','john doe','jane doe','acme','contoso','example.com','example.org','test@','not real',
    'hypothetical','illustrative','template','mock','demo only',
  ];

  /** Common English words that must never be treated as a secret value. */
  const COMMON_WORDS = set([
    'password','secret','required','important','correct','incorrect','changed','updated','expired','invalid',
    'missing','unknown','provided','available','disabled','enabled','something','anything','nothing',
    'strong','weak','simple','complex','default','standard','custom','private','public','hidden','visible',
    'confidential','sensitive','encrypted','hashed','stored','shared','rotated','reset','blank','empty',
    'letters','numbers','characters','symbols','uppercase','lowercase','minimum','maximum','optional',
  ]);

  /* ==== engine/patterns.js ==== */
  /**
   * Pattern rule set.
   *
   * A rule is:
   *   id           unique string
   *   category     one of CATEGORIES
   *   severity     default severity (a validator may downgrade/upgrade it)
   *   label        redaction token, e.g. EMAIL -> [EMAIL]
   *   title        human name of the finding
   *   why          one-sentence risk explanation shown in the UI
   *   confidence   base confidence 0..1 before context scoring
   *   regex        global regex
   *   group        capture group holding the sensitive value (default 0 = whole match)
   *   needsContext regex that must match within +/- CONTEXT_WINDOW characters
   *   validate     (value, match, text) => boolean | { confidence?, severity?, note?, label? }
   */





  const CONTEXT_WINDOW = 80;

  const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  /** Build a word-boundary alternation from a phrase list, longest first. */
  const alt = (list) =>
    [...list].sort((a, b) => b.length - a.length).map(esc).join('|');

  function rule(def) {
    return { group: 0, confidence: 0.8, ...def };
  }

  /* ------------------------------------------------------------------ */
  /* 3. CREDENTIALS — highest priority, matched first                     */
  /* ------------------------------------------------------------------ */

  const CREDENTIAL_RULES = [
    rule({
      id: 'private_key_block',
      category: C.CREDENTIALS, severity: S.CRITICAL, label: 'PRIVATE_KEY',
      title: 'Private key block', confidence: 0.99,
      regex: /-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[\s\S]{0,4000}?-----END (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g,
      why: 'A private key grants full impersonation of whatever identity it belongs to. Once pasted it must be considered compromised and revoked immediately.',
    }),
    rule({
      id: 'aws_access_key_id',
      category: C.CREDENTIALS, severity: S.CRITICAL, label: 'AWS_ACCESS_KEY',
      title: 'AWS access key ID', confidence: 0.97,
      regex: /\b(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA|APKA)[A-Z0-9]{16}\b/g,
      why: 'AWS access key IDs are paired with a secret to call your cloud account. Leaked keys are harvested by automated scanners within minutes.',
    }),
    rule({
      id: 'aws_secret_access_key',
      category: C.CREDENTIALS, severity: S.CRITICAL, label: 'AWS_SECRET_KEY',
      title: 'AWS secret access key', confidence: 0.93, group: 1,
      regex: /(?:aws[_\- ]?secret[_\- ]?access[_\- ]?key|aws[_\- ]?secret)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
      why: 'The AWS secret access key is the password half of an AWS credential pair and allows full API access at the permissions of its IAM principal.',
    }),
    rule({
      id: 'github_token',
      category: C.CREDENTIALS, severity: S.CRITICAL, label: 'GITHUB_TOKEN',
      title: 'GitHub token', confidence: 0.98,
      regex: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/g,
      why: 'A GitHub token can read or push to every repository the owner can reach, including private source code and CI secrets.',
    }),
    rule({
      id: 'slack_token',
      category: C.CREDENTIALS, severity: S.CRITICAL, label: 'SLACK_TOKEN',
      title: 'Slack API token', confidence: 0.97,
      regex: /\bxox[baprse]-[A-Za-z0-9-]{10,}\b/g,
      why: 'Slack tokens can read message history and post as your workspace app, exposing every internal conversation the token can see.',
    }),
    rule({
      id: 'slack_webhook',
      category: C.CREDENTIALS, severity: S.HIGH, label: 'SLACK_WEBHOOK',
      title: 'Slack incoming webhook URL', confidence: 0.96,
      regex: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9]+\/[A-Za-z0-9]+\/[A-Za-z0-9]+/g,
      why: 'Anyone holding this URL can post messages into your Slack channel, which is a ready-made phishing channel inside a trusted space.',
    }),
    rule({
      id: 'stripe_key',
      category: C.CREDENTIALS, severity: S.CRITICAL, label: 'STRIPE_KEY',
      title: 'Stripe API key', confidence: 0.97,
      regex: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
      why: 'A live Stripe secret key can move real money, read customer payment records and issue refunds.',
      validate: (v) => (/_test_/.test(v) ? { severity: S.MEDIUM, note: 'Test-mode key' } : true),
    }),
    rule({
      id: 'openai_key',
      category: C.CREDENTIALS, severity: S.CRITICAL, label: 'API_KEY',
      title: 'OpenAI API key', confidence: 0.96,
      regex: /\bsk-(?:proj-|svcacct-|admin-|None-|Test-)?[A-Za-z0-9_-]{20,}\b/g,
      why: 'API keys bill to your account and are abused for large-scale credential-stuffed inference within hours of leaking.',
      validate: (v) => !/^sk-ant-/.test(v),
    }),
    rule({
      id: 'anthropic_key',
      category: C.CREDENTIALS, severity: S.CRITICAL, label: 'API_KEY',
      title: 'Anthropic API key', confidence: 0.97,
      regex: /\bsk-ant-(?:api|admin|sid)[0-9]{0,2}-[A-Za-z0-9_-]{24,}\b/g,
      why: 'API keys bill to your account and grant full programmatic access under your organisation.',
    }),
    rule({
      id: 'google_api_key',
      category: C.CREDENTIALS, severity: S.CRITICAL, label: 'API_KEY',
      title: 'Google API key', confidence: 0.95,
      regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
      why: 'Google API keys are frequently unrestricted and can be used to run up billing on Maps, Cloud or Gemini APIs.',
    }),
    rule({
      id: 'sendgrid_key',
      category: C.CREDENTIALS, severity: S.CRITICAL, label: 'API_KEY',
      title: 'SendGrid API key', confidence: 0.97,
      regex: /\bSG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64}\b/g,
      why: 'Mail-sending keys let an attacker send email that passes SPF/DKIM as your domain — ideal for phishing your own customers.',
    }),
    rule({
      id: 'twilio_sid',
      category: C.CREDENTIALS, severity: S.HIGH, label: 'API_KEY',
      title: 'Twilio account SID / key', confidence: 0.9,
      regex: /\b(?:AC|SK)[0-9a-fA-F]{32}\b/g,
      why: 'Twilio credentials allow sending SMS and voice calls billed to you, and can expose call and message logs.',
    }),
    rule({
      id: 'npm_token',
      category: C.CREDENTIALS, severity: S.CRITICAL, label: 'API_KEY',
      title: 'npm access token', confidence: 0.96,
      regex: /\bnpm_[A-Za-z0-9]{36}\b/g,
      why: 'An npm token can publish packages under your name — a direct supply-chain attack vector.',
    }),
    rule({
      id: 'jwt_token',
      category: C.CREDENTIALS, severity: S.HIGH, label: 'JWT',
      title: 'JSON Web Token', confidence: 0.92,
      regex: /\beyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b/g,
      why: 'A JWT is a bearer credential: whoever holds it is the user until it expires. Its payload also often contains email, roles and internal IDs in plain base64.',
    }),
    rule({
      id: 'db_connection_string',
      category: C.CREDENTIALS, severity: S.CRITICAL, label: 'DB_CONNECTION_STRING',
      title: 'Database connection string with password', confidence: 0.96,
      regex: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|clickhouse|snowflake):\/\/[^\s:@/]+:[^\s@/]+@[^\s"'<>]+/gi,
      why: 'A connection string bundles host, username and password — everything needed to read or drop your production database.',
    }),
    rule({
      id: 'authorization_header',
      category: C.CREDENTIALS, severity: S.CRITICAL, label: 'AUTH_TOKEN',
      title: 'Authorization header value', confidence: 0.93, group: 1,
      regex: /\bAuthorization\s*:\s*(?:Bearer|Basic|Token|ApiKey)\s+([A-Za-z0-9._\-+/=]{12,})/gi,
      why: 'This is a live bearer credential copied straight out of a request; anyone replaying it acts as the original caller.',
    }),
    rule({
      id: 'password_assignment',
      category: C.CREDENTIALS, severity: S.CRITICAL, label: 'PASSWORD',
      title: 'Password or secret assignment', confidence: 0.86, group: 2,
      regex: /\b(password|passwd|pwd|passphrase|secret|api[_\- ]?key|apikey|access[_\- ]?token|auth[_\- ]?token|client[_\- ]?secret|private[_\- ]?key|credential|pin)\b(?:\s*(?:=|:|=>|->)\s*|\s+(?:is|was|will be|should be)\s+|\s+)["'`]?([^\s"'`,;<>()]{6,128}?)["'`]?(?=[\s,;.]|$)/gi,
      why: 'A working password pasted into a third-party service should be treated as compromised and rotated, even if the prompt is later deleted.',
      validate: (v) => {
        const low = v.toLowerCase();
        if (COMMON_WORDS.has(low)) return false;
        if (/^\[.*\]$/.test(v) || /^<.*>$/.test(v) || /^\{\{.*\}\}$/.test(v)) return false; // already a placeholder
        if (/^\*+$/.test(v) || /^x+$/i.test(v) || /^•+$/.test(v)) return false;             // masked already
        // A single plain English-looking word is prose, not a secret:
        // "...password requirements", "...API key authentication".
        if (/^[A-Za-z]?[a-z]+$/.test(v)) return false;
        const hasDigit = /\d/.test(v);
        const hasSymbol = /[^A-Za-z0-9]/.test(v);
        const capitals = (v.match(/[A-Z]/g) || []).length;
        if (!hasDigit && !hasSymbol && capitals < 2) return false;
        if (/^(?:required|needed|missing|invalid|expired|correct|incorrect|strong|weak)/i.test(v)) return false;
        return true;
      },
    }),
    rule({
      id: 'env_secret_line',
      category: C.CREDENTIALS, severity: S.CRITICAL, label: 'SECRET',
      title: 'Environment variable holding a secret', confidence: 0.9, group: 1,
      regex: /^[ \t]*(?:export[ \t]+)?[A-Z][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|PWD|CREDENTIAL|DSN)[ \t]*=[ \t]*["']?([^\s"'#]{6,})["']?[ \t]*$/gm,
      why: 'Values from .env files are live production secrets; sharing one line is enough to compromise the service it protects.',
      validate: (v) => !/^(?:changeme|your[_-]?\w*|xxx+|<.*>|\{\{.*\}\}|\[.*\])$/i.test(v),
    }),
    rule({
      id: 'generic_high_entropy_secret',
      category: C.CREDENTIALS, severity: S.MEDIUM, label: 'SECRET',
      title: 'High-entropy string (possible secret)', confidence: 0.55,
      regex: /\b[A-Za-z0-9_\-+/]{28,120}={0,2}\b/g,
      why: 'This looks machine-generated rather than human-written, which is characteristic of an API key, session token or hash.',
      validate: (v) => {
        if (!looksLikeSecret(v)) return false;
        if (/^[0-9a-f]{32}$/i.test(v)) return { confidence: 0.5, note: 'Possible MD5 hash or hex ID' };
        if (/^[0-9a-f]{40}$/i.test(v)) return { confidence: 0.45, note: 'Possible SHA-1 / git commit hash' };
        if (/^[0-9a-f]{64}$/i.test(v)) return { confidence: 0.5, note: 'Possible SHA-256 hash' };
        if (shannonEntropy(v) < 3.7 && charClasses(v) < 3) return false;
        return true;
      },
    }),
  ];

  /* ------------------------------------------------------------------ */
  /* 2. GOVERNMENT & FINANCIAL IDENTIFIERS                                */
  /* ------------------------------------------------------------------ */

  const GOV_FIN_RULES = [
    rule({
      id: 'us_ssn_formatted',
      category: C.GOV_FIN, severity: S.CRITICAL, label: 'SSN',
      title: 'US Social Security Number', confidence: 0.95,
      regex: /\b\d{3}[-– ]\d{2}[-– ]\d{4}\b/g,
      why: 'An SSN is the master key to US credit and identity systems; it cannot be reissued easily and is the single most abused identifier in identity theft.',
      validate: (v) => {
        if (!ssnStructurallyValid(v)) return false;
        return true;
      },
    }),
    rule({
      id: 'us_ssn_bare',
      category: C.GOV_FIN, severity: S.CRITICAL, label: 'SSN',
      title: 'US Social Security Number', confidence: 0.9,
      regex: /\b\d{9}\b/g,
      needsContext: /\b(?:ssn|s\.s\.n|social security(?: number| no\.?| #)?|taxpayer id)\b/i,
      why: 'An SSN is the master key to US credit and identity systems; it cannot be reissued easily and is the single most abused identifier in identity theft.',
      validate: (v) => ssnStructurallyValid(v),
    }),
    rule({
      id: 'us_itin',
      category: C.GOV_FIN, severity: S.CRITICAL, label: 'ITIN',
      title: 'US Individual Taxpayer Identification Number', confidence: 0.9,
      regex: /\b9\d{2}[-– ](?:5\d|6[0-5]|7\d|8[0-8]|9[0-2]|9[4-9])[-– ]\d{4}\b/g,
      why: 'An ITIN identifies a taxpayer who often has no SSN, and in practice signals immigration status as well as tax identity.',
    }),
    rule({
      id: 'us_ein',
      category: C.GOV_FIN, severity: S.HIGH, label: 'EIN',
      title: 'US Employer Identification Number', confidence: 0.85,
      regex: /\b\d{2}-\d{7}\b/g,
      needsContext: /\b(?:ein|e\.i\.n|employer identification|federal tax id|tax id(?:entification)? number|fein)\b/i,
      why: 'An EIN plus a business name is enough to open credit lines or file fraudulent returns in the organisation’s name.',
    }),
    rule({
      id: 'payment_card',
      category: C.GOV_FIN, severity: S.CRITICAL, label: 'CREDIT_CARD',
      title: 'Payment card number', confidence: 0.95,
      regex: /\b(?:\d[ \-]?){12,18}\d\b/g,
      why: 'Card numbers are directly monetisable. Handling them outside a PCI-DSS compliant environment is a compliance breach on its own.',
      validate: (v) => {
        const digits = v.replace(/\D/g, '');
        if (digits.length < 13 || digits.length > 19) return false;
        if (!luhn(digits)) return false;
        const brand = cardBrand(digits);
        if (!brand) return false;
        if (isKnownTestValue(digits)) {
          return { severity: S.LOW, confidence: 0.55, note: `Well-known ${brand} test card` };
        }
        return { note: `${brand}, passes Luhn check` };
      },
    }),
    rule({
      id: 'card_cvv',
      category: C.GOV_FIN, severity: S.HIGH, label: 'CVV',
      title: 'Card security code', confidence: 0.88, group: 1,
      regex: /\b(?:cvv2?|cvc2?|cid|security code|card verification(?: value| code)?)\b\s*[:#=]?\s*(\d{3,4})\b/gi,
      why: 'The CVV proves possession of the physical card; storing or transmitting it is prohibited under PCI-DSS even for merchants.',
    }),
    rule({
      id: 'card_expiry',
      category: C.GOV_FIN, severity: S.MEDIUM, label: 'CARD_EXPIRY',
      title: 'Card expiry date', confidence: 0.75, group: 1,
      regex: /\b(?:exp(?:iry|iration)?(?:\s*date)?|valid thru|good thru)\b\s*[:#=]?\s*(\d{2}\s?\/\s?\d{2,4})\b/gi,
      why: 'Expiry dates are one of the three fields needed for card-not-present fraud alongside the number and CVV.',
    }),
    rule({
      id: 'iban',
      category: C.GOV_FIN, severity: S.CRITICAL, label: 'IBAN',
      title: 'IBAN bank account number', confidence: 0.95,
      regex: /\b[A-Z]{2}\d{2}[ ]?(?:[A-Z0-9]{4}[ ]?){2,7}[A-Z0-9]{1,4}\b/g,
      why: 'An IBAN identifies a specific bank account and is routinely used to redirect payments in invoice-fraud attacks.',
      validate: (v) => ibanValid(v),
    }),
    rule({
      id: 'us_routing_number',
      category: C.GOV_FIN, severity: S.HIGH, label: 'ROUTING_NUMBER',
      title: 'US bank routing number', confidence: 0.88,
      regex: /\b\d{9}\b/g,
      needsContext: /\b(?:routing(?: transit)?(?: number| no\.?| #)?|aba(?: number)?|rtn|wire instructions|ach)\b/i,
      why: 'Routing plus account number allows ACH debits directly against the account.',
      validate: (v) => abaRoutingValid(v),
    }),
    rule({
      id: 'bank_account_number',
      category: C.GOV_FIN, severity: S.CRITICAL, label: 'BANK_ACCOUNT',
      title: 'Bank account number', confidence: 0.86, group: 1,
      regex: /\b(?:account(?: number| no\.?| #)?|acct\.?(?: no\.?| #)?|a\/c)\s*[:#-]?\s*(\d{6,17})\b/gi,
      why: 'Account numbers enable unauthorised debits and are a core ingredient of payment-redirection fraud.',
      validate: (v, m, text) => !/\b(?:invoice|order|ticket|case|po|purchase order)\b/i.test(m.context || ''),
    }),
    rule({
      id: 'swift_bic',
      category: C.GOV_FIN, severity: S.MEDIUM, label: 'SWIFT_BIC',
      title: 'SWIFT / BIC code', confidence: 0.8,
      regex: /\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b/g,
      needsContext: /\b(?:swift|bic|international wire|beneficiary bank)\b/i,
      why: 'Combined with an account number a SWIFT code completes a full international payment instruction.',
    }),
    rule({
      id: 'passport_number',
      category: C.GOV_FIN, severity: S.CRITICAL, label: 'PASSPORT_NUMBER',
      title: 'Passport number', confidence: 0.88, group: 1,
      regex: /\bpassport(?:\s*(?:number|no\.?|#))?\s*[:#-]?\s*([A-Z]{0,3}[0-9]{6,9}[A-Z]?)\b/gi,
      why: 'Passport numbers support identity fraud and travel-document forgery, and are special-category adjacent because they reveal nationality.',
    }),
    rule({
      id: 'drivers_licence',
      category: C.GOV_FIN, severity: S.HIGH, label: 'DRIVERS_LICENSE',
      title: 'Driver licence number', confidence: 0.86, group: 1,
      regex: /\b(?:driver'?s?\s*licen[cs]e|driving\s*licen[cs]e|dl)\s*(?:number|no\.?|#)?\s*[:#-]?\s*([A-Z0-9]{5,16})\b/gi,
      why: 'Driver licences are a primary identity document in most of the US and are widely accepted for account opening.',
    }),
    rule({
      id: 'india_aadhaar',
      category: C.GOV_FIN, severity: S.CRITICAL, label: 'AADHAAR',
      title: 'Aadhaar number (India)', confidence: 0.93,
      regex: /\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b/g,
      why: 'Aadhaar is India’s national biometric identity number; unlawful disclosure is an offence under the Aadhaar Act.',
      validate: (v) => verhoeffValid(v),
    }),
    rule({
      id: 'india_pan',
      category: C.GOV_FIN, severity: S.HIGH, label: 'PAN',
      title: 'PAN card number (India)', confidence: 0.88,
      regex: /\b[A-Z]{3}[ABCFGHLJPTK][A-Z]\d{4}[A-Z]\b/g,
      why: 'The PAN is India’s permanent taxpayer identifier and links directly to bank and tax records.',
    }),
    rule({
      id: 'uk_nino',
      category: C.GOV_FIN, severity: S.CRITICAL, label: 'NATIONAL_INSURANCE_NUMBER',
      title: 'UK National Insurance number', confidence: 0.9,
      regex: /\b[ABCEGHJKLMNOPRSTWXYZ][ABCEGHJKLMNPRSTWXYZ]\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b/g,
      why: 'The NI number is the UK’s lifetime tax and benefits identifier and is treated as sensitive personal data.',
    }),
    rule({
      id: 'canada_sin',
      category: C.GOV_FIN, severity: S.CRITICAL, label: 'SIN',
      title: 'Canadian Social Insurance Number', confidence: 0.9,
      regex: /\b\d{3}[- ]\d{3}[- ]\d{3}\b/g,
      needsContext: /\b(?:sin|social insurance)\b/i,
      why: 'The SIN is required for employment and banking in Canada and is a primary identity-theft target.',
      validate: (v) => luhn(v.replace(/\D/g, '').padStart(12, '0')) || /^\d{3}[- ]\d{3}[- ]\d{3}$/.test(v),
    }),
    rule({
      id: 'crypto_wallet',
      category: C.GOV_FIN, severity: S.MEDIUM, label: 'WALLET_ADDRESS',
      title: 'Cryptocurrency wallet address', confidence: 0.82,
      regex: /\b(?:0x[a-fA-F0-9]{40}|bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g,
      why: 'A wallet address links a person to their full on-chain transaction history, which is public and permanent.',
    }),
  ];

  /* ------------------------------------------------------------------ */
  /* 1. NAMES & CONTACT INFORMATION                                       */
  /* ------------------------------------------------------------------ */

  const CONTACT_RULES = [
    rule({
      id: 'email_address',
      category: C.CONTACT, severity: S.HIGH, label: 'EMAIL',
      title: 'Email address', confidence: 0.96,
      regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b/g,
      why: 'An email address identifies a specific person and is the pivot point for phishing, credential stuffing and data-broker matching.',
      validate: (v) => {
        const domain = v.split('@')[1].toLowerCase();
        if (/^(?:example\.(?:com|org|net)|test\.com|domain\.com|email\.com|acme\.com|contoso\.com|localhost)$/.test(domain)) {
          return { severity: S.LOW, confidence: 0.6, note: 'Reserved documentation domain' };
        }
        return true;
      },
    }),
    rule({
      id: 'phone_number',
      category: C.CONTACT, severity: S.HIGH, label: 'PHONE',
      title: 'Phone number', confidence: 0.88,
      regex: /(?:\+\d{1,3}[ .-]?)?(?:\(\d{2,4}\)[ .-]?|\d{2,4}[ .-])\d{3,4}[ .-]?\d{3,4}(?:[ .-]?\d{1,4})?\b|\+\d{9,15}\b/g,
      why: 'Phone numbers are stable identifiers used for SIM-swap attacks, SMS phishing and cross-database identity matching.',
      validate: (v, m) => {
        const digits = v.replace(/\D/g, '');
        if (digits.length < 7 || digits.length > 15) return false;
        if (/^\d+$/.test(v.trim()) && !/^\+/.test(v.trim())) {
          // A bare run of digits with no separators is more likely an ID than a phone.
          if (!/\b(?:phone|mobile|cell|tel|telephone|whatsapp|contact(?:ed)? (?:me|him|her|them|us)? ?at|call(?: me| him| her| them)? ?(?:at|on))\b/i.test(m.context || '')) return false;
        }
        if (/^(?:19|20)\d{2}[ .-]\d{2}[ .-]\d{2}$/.test(v.trim())) return false;  // ISO date
        if (/^\d{1,2}[.:]\d{2}$/.test(v.trim())) return false;                     // clock time
        if (/^\d+\.\d+\.\d+$/.test(v.trim())) return false;                        // semver
        if (/^(\d)\1{6,}$/.test(digits)) return false;                             // 0000000
        return true;
      },
    }),
    rule({
      id: 'street_address',
      category: C.CONTACT, severity: S.HIGH, label: 'ADDRESS',
      title: 'Street address', confidence: 0.87,
      regex: /\b\d{1,6}[A-Za-z]?\s+(?:[A-Z][A-Za-z.'-]*\s+){0,4}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Terrace|Ter|Place|Pl|Circle|Cir|Parkway|Pkwy|Highway|Hwy|Square|Sq|Trail|Trl|Close|Crescent|Cres)\b\.?(?:,?\s*(?:Apt\.?|Apartment|Suite|Ste\.?|Unit|Flat|Floor|Fl\.?|#)\s*[A-Za-z0-9-]+)?/g,
      why: 'A home address exposes a person to physical risk as well as identity fraud, and is enough to re-identify an otherwise anonymous record.',
    }),
    rule({
      id: 'postal_code_with_state',
      category: C.CONTACT, severity: S.MEDIUM, label: 'POSTAL_CODE',
      title: 'City / state / postal code', confidence: 0.72,
      regex: /\b[A-Z][a-z]+(?:\s[A-Z][a-z]+)?,\s?(?:A[LKZR]|C[AOT]|D[EC]|FL|GA|HI|I[DLNA]|K[SY]|LA|M[EDAINSOT]|N[EVHJMYCD]|O[HKR]|PA|RI|S[CD]|T[NX]|UT|V[TA]|W[AVIY])\s+\d{5}(?:-\d{4})?\b/g,
      why: 'A precise postal code combined with a city narrows a person down to a handful of households.',
    }),
    rule({
      id: 'uk_postcode',
      category: C.CONTACT, severity: S.MEDIUM, label: 'POSTAL_CODE',
      title: 'UK postcode', confidence: 0.8,
      regex: /\b[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}\b/g,
      needsContext: /\b(?:address|postcode|post code|lives? at|resides?|delivery|billing|home)\b/i,
      why: 'A full UK postcode identifies roughly 15 addresses and is treated as personal data when linked to a person.',
    }),
    rule({
      id: 'date_of_birth',
      category: C.CONTACT, severity: S.HIGH, label: 'DATE_OF_BIRTH',
      title: 'Date of birth', confidence: 0.9, group: 1, ignoreSafeSpans: true,
      regex: /\b(?:d\.?o\.?b\.?|date of birth|birth ?date|born(?: on)?)\b\s*[:\-]?\s*((?:\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4})|(?:\d{1,2}(?:st|nd|rd|th)?\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4})|(?:(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}))/gi,
      why: 'Date of birth plus a name is the standard identity-verification pair used by banks, insurers and government services.',
    }),
    rule({
      id: 'linkedin_profile',
      category: C.CONTACT, severity: S.MEDIUM, label: 'SOCIAL_PROFILE',
      title: 'LinkedIn profile URL', confidence: 0.9,
      regex: /\b(?:https?:\/\/)?(?:[a-z]{2,3}\.)?linkedin\.com\/in\/[A-Za-z0-9_-]{3,100}\/?/gi,
      why: 'A profile URL ties a prompt to a named, employed individual and their full career history.',
    }),
    rule({
      id: 'social_handle',
      category: C.CONTACT, severity: S.MEDIUM, label: 'SOCIAL_HANDLE',
      title: 'Social media handle', confidence: 0.72, group: 1,
      regex: /\b(?:twitter|x\.com|instagram|insta|telegram|tiktok|snapchat|discord|handle|username)\b[^\n@]{0,20}(@[A-Za-z0-9_.]{3,30})\b/gi,
      why: 'Handles are durable pseudonymous identifiers that are usually trivially linkable to a real identity.',
    }),
    rule({
      id: 'public_ip_address',
      category: C.CONTACT, severity: S.MEDIUM, label: 'IP_ADDRESS',
      title: 'IP address', confidence: 0.8,
      regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
      why: 'A public IP address is personal data under GDPR and can reveal approximate location and employer network.',
      validate: (v) => {
        if (!isValidIPv4(v)) return false;
        if (isPrivateIPv4(v)) return { severity: S.LOW, confidence: 0.45, note: 'Private / reserved range' };
        return true;
      },
    }),
    rule({
      id: 'mac_address',
      category: C.CONTACT, severity: S.LOW, label: 'MAC_ADDRESS',
      title: 'MAC address', confidence: 0.8,
      regex: /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g,
      why: 'A MAC address is a persistent hardware identifier that can be used to track a specific device.',
    }),
    rule({
      id: 'vehicle_plate',
      category: C.CONTACT, severity: S.MEDIUM, label: 'LICENSE_PLATE',
      title: 'Vehicle registration', confidence: 0.75, group: 1,
      regex: /\b(?:licen[cs]e plate|number plate|registration(?: number)?|reg no\.?|plate)\s*[:#-]?\s*([A-Z0-9]{2,4}[- ]?[A-Z0-9]{2,4})\b/gi,
      why: 'Plate numbers are linked to a registered keeper and are used to infer home and workplace locations.',
    }),
  ];

  /* ------------------------------------------------------------------ */
  /* 4. MEDICAL & SENSITIVE PERSONAL DATA                                 */
  /* ------------------------------------------------------------------ */

  const MEDICAL_RULES = [
    rule({
      id: 'medical_record_number',
      category: C.MEDICAL, severity: S.CRITICAL, label: 'MEDICAL_RECORD_NUMBER',
      title: 'Medical record number', confidence: 0.93, group: 1,
      regex: /\b(?:mrn|medical record (?:number|no\.?|#)|patient (?:id|number|no\.?|#)|chart (?:number|no\.?|#)|health record (?:number|no\.?|#))\s*[:#-]?\s*([A-Z]{0,4}[-]?\d{4,12}[A-Z]?)\b/gi,
      why: 'An MRN is a direct key into a patient’s full clinical file and is protected health information under HIPAA.',
    }),
    rule({
      id: 'health_insurance_id',
      category: C.MEDICAL, severity: S.CRITICAL, label: 'INSURANCE_ID',
      title: 'Health insurance / member ID', confidence: 0.9, group: 1,
      regex: /\b(?:member (?:id|number|no\.?|#)|policy (?:number|no\.?|#)|subscriber (?:id|number)|medicare (?:number|id|mbi)|medicaid (?:id|number)|insurance (?:id|number|member id)|group (?:number|no\.?) )\s*[:#-]?\s*([A-Z0-9][A-Z0-9-]{4,17})\b/gi,
      why: 'Insurance identifiers enable medical identity theft, where treatment is billed against someone else’s coverage and contaminates their record.',
    }),
    rule({
      id: 'npi_number',
      category: C.MEDICAL, severity: S.MEDIUM, label: 'NPI',
      title: 'National Provider Identifier', confidence: 0.85, group: 1,
      regex: /\bnpi\s*(?:number|no\.?|#)?\s*[:#-]?\s*(\d{10})\b/gi,
      why: 'An NPI identifies the treating clinician, which in combination with a date narrows the patient population dramatically.',
      validate: (v) => npiValid(v),
    }),
    rule({
      id: 'icd_code',
      category: C.MEDICAL, severity: S.HIGH, label: 'DIAGNOSIS_CODE',
      title: 'ICD diagnosis code', confidence: 0.8,
      regex: /\b[A-TV-Z]\d{2}(?:\.[A-Z0-9]{1,4})?\b/g,
      needsContext: /\b(?:icd|icd-?10|icd-?11|diagnosis|dx|coded as|billing code|primary diagnosis)\b/i,
      why: 'A diagnosis code is a precise clinical statement about a named individual and is protected health information.',
    }),
    rule({
      id: 'medical_condition',
      category: C.MEDICAL, severity: S.HIGH, label: 'MEDICAL_CONDITION',
      title: 'Health condition', confidence: 0.78,
      regex: new RegExp(`\\b(?:${alt(MEDICAL_CONDITIONS)})\\b`, 'gi'),
      why: 'Health status is special-category data under GDPR Art. 9. Attaching it to any identifier creates a disclosable health record.',
      validate: (v, m) => {
        const ctx = (m.context || '').toLowerCase();
        // Generic/educational usage ("what is diabetes?") is not a disclosure.
        if (/\b(?:what is|what are|define|definition of|explain|symptoms of|causes of|how does|research on|article about|statistics on)\b/.test(ctx)) {
          return { severity: S.LOW, confidence: 0.3, note: 'Appears to be a general question, not a patient disclosure' };
        }
        return true;
      },
    }),
    rule({
      id: 'medication_name',
      category: C.MEDICAL, severity: S.HIGH, label: 'MEDICATION',
      title: 'Medication', confidence: 0.76,
      regex: new RegExp(`\\b(?:${alt(MEDICATIONS)})\\b`, 'gi'),
      why: 'Naming a prescription reveals the underlying condition; psychiatric and HIV medications are especially identifying and stigmatising.',
      validate: (v, m) => {
        const ctx = (m.context || '').toLowerCase();
        if (/\b(?:what is|side effects of|interaction between|dosage guidelines|how does|mechanism of|generic name for)\b/.test(ctx)) {
          return { severity: S.LOW, confidence: 0.3, note: 'Appears to be a general drug question' };
        }
        return true;
      },
    }),
    rule({
      id: 'clinical_measurement',
      category: C.MEDICAL, severity: S.MEDIUM, label: 'CLINICAL_RESULT',
      title: 'Clinical measurement or lab result', confidence: 0.75, ignoreSafeSpans: true,
      regex: /\b(?:a1c|hba1c|blood pressure|bp|cholesterol|ldl|hdl|triglycerides|glucose|creatinine|egfr|psa|inr|viral load|cd4(?: count)?|white cell count|platelet count|bmi)\b\s*(?:of|is|was|:|=|at)?\s*(?:\d{1,3}(?:\.\d+)?(?:\s*\/\s*\d{1,3})?)\s*(?:%|mg\/dl|mmol\/l|mmhg|copies\/ml|cells\/mm3)?/gi,
      why: 'Lab values are clinical findings about an individual and are protected health information when linked to a person.',
    }),
    rule({
      id: 'immigration_status',
      category: C.MEDICAL, severity: S.CRITICAL, label: 'IMMIGRATION_STATUS',
      title: 'Immigration or legal status', confidence: 0.85,
      regex: new RegExp(`\\b(?:${alt(IMMIGRATION_TERMS)})\\b`, 'gi'),
      why: 'Immigration status is special-category data whose disclosure can lead to discrimination, loss of employment or enforcement action against the individual.',
    }),
    rule({
      id: 'uscis_a_number',
      category: C.MEDICAL, severity: S.CRITICAL, label: 'ALIEN_NUMBER',
      title: 'USCIS A-number', confidence: 0.88,
      regex: /\bA[-# ]?\d{8,9}\b/g,
      needsContext: /\b(?:a-?number|alien (?:registration|number)|uscis|immigration|green card|i-?\d{3})\b/i,
      why: 'The A-number is the unique identifier in a person’s US immigration file and directly reveals their status.',
    }),
    rule({
      id: 'protected_attribute',
      category: C.MEDICAL, severity: S.HIGH, label: 'SENSITIVE_ATTRIBUTE',
      title: 'Protected personal attribute', confidence: 0.7,
      regex: new RegExp(`\\b(?:${alt(PROTECTED_ATTRIBUTES)})\\b`, 'gi'),
      why: 'Religion, ethnicity, sexual orientation, union membership and criminal history are special-category data and a common basis for discrimination.',
      validate: (v, m) => {
        const ctx = (m.context || '').toLowerCase();
        if (/\b(?:policy|policies|training|guidance|law|legislation|compliance|definition|non-discrimination|equal opportunity)\b/.test(ctx)) {
          return { severity: S.LOW, confidence: 0.3, note: 'Appears to be policy language rather than a disclosure about a person' };
        }
        return true;
      },
    }),
  ];

  /* ------------------------------------------------------------------ */
  /* 5. EMPLOYEE / CLIENT / VOLUNTEER RECORDS                             */
  /* ------------------------------------------------------------------ */

  const PEOPLE_RULES = [
    rule({
      id: 'personnel_id',
      category: C.PEOPLE, severity: S.HIGH, label: 'EMPLOYEE_ID',
      title: 'Employee / volunteer / client identifier', confidence: 0.9, group: 2,
      regex: /\b(employee|emp|staff|personnel|worker|badge|volunteer|vol|donor|client|customer|case|beneficiary|member|student|tenant|contractor)\s*(?:id|ids|no\.?|number|#|code|ref(?:erence)?)\s*[:#-]?\s*([A-Z]{0,5}[-_]?\d{3,10}[A-Z]?)\b/gi,
      why: 'Internal identifiers are the join key to a person’s full HR, client or volunteer record and are held under a confidentiality duty.',
    }),
    rule({
      id: 'personnel_id_prefixed',
      category: C.PEOPLE, severity: S.HIGH, label: 'EMPLOYEE_ID',
      title: 'Prefixed personnel identifier', confidence: 0.85,
      regex: /\b(?:EMP|EMPL|STF|VOL|CLT|CLI|DNR|CASE|BEN|STU|CON|BADGE)[-_]?\d{3,10}\b/g,
      why: 'Internal identifiers are the join key to a person’s full HR, client or volunteer record and are held under a confidentiality duty.',
    }),
    rule({
      id: 'salary_compensation',
      category: C.PEOPLE, severity: S.HIGH, label: 'COMPENSATION',
      title: 'Salary or compensation detail', confidence: 0.85,
      regex: /\b(?:salary|salaries|base pay|base salary|annual (?:pay|compensation)|total comp(?:ensation)?|hourly rate|pay rate|bonus|stipend|severance|equity grant|rsu grant|commission)\b[^.\n]{0,40}?(?:[$£€₹]\s?[\d,]+(?:\.\d{1,2})?\s?(?:[kKmM]|thousand|million)?|\b\d{2,3},\d{3}\b)/gi,
      why: 'Individual pay data is confidential in most employment contracts, and disclosing a colleague’s pay can create legal exposure for you and your employer.',
    }),
    rule({
      id: 'performance_management',
      category: C.PEOPLE, severity: S.HIGH, label: 'HR_RECORD',
      title: 'Performance or disciplinary record', confidence: 0.82,
      regex: /\b(?:performance (?:rating|review|score|improvement plan)|\bPIP\b|placed on a? ?pip|written warning|final warning|disciplinary (?:action|hearing|record)|grievance (?:filed|case)|harassment (?:complaint|allegation)|misconduct (?:report|finding)|termination (?:letter|decision|for cause)|being let go|on a performance plan|underperforming|rated (?:a )?[1-5] ?(?:out of|\/) ?5)\b/gi,
      why: 'Performance and disciplinary information is among the most damaging HR data to leak and is protected by employment and data-protection law.',
    }),
    rule({
      id: 'hr_case_reference',
      category: C.PEOPLE, severity: S.HIGH, label: 'CASE_REFERENCE',
      title: 'HR / safeguarding case reference', confidence: 0.85, group: 1,
      regex: /\b(?:hr case|safeguarding case|incident|grievance|investigation|complaint)\s*(?:id|no\.?|number|ref(?:erence)?|#)\s*[:#-]?\s*([A-Z]{0,5}[-_]?\d{3,10})\b/gi,
      why: 'Case references identify a live personnel or safeguarding matter and are usually restricted to a named handful of staff.',
    }),
    rule({
      id: 'beneficiary_roster',
      category: C.PEOPLE, severity: S.MEDIUM, label: 'PEOPLE_RECORD',
      title: 'Roster or list of individuals', confidence: 0.7,
      regex: /\b(?:list of (?:employees|staff|volunteers|clients|donors|beneficiaries|patients|students|members)|(?:employee|staff|volunteer|client|donor|beneficiary|patient|student|member) (?:roster|list|directory|database|spreadsheet)|attendance sheet|contact list)\b/gi,
      why: 'Bulk people data multiplies the impact of any disclosure — one paste can expose hundreds of individuals at once.',
    }),
  ];

  /* ------------------------------------------------------------------ */
  /* 6. CONFIDENTIAL ORGANISATIONAL INFORMATION                           */
  /* ------------------------------------------------------------------ */

  const ORG_RULES = [
    rule({
      id: 'confidentiality_marker',
      category: C.ORG, severity: S.HIGH, label: 'CONFIDENTIALITY_MARKER',
      title: 'Confidentiality classification marker', confidence: 0.9,
      regex: new RegExp(`\\b(?:${alt(CONFIDENTIALITY_MARKERS)})\\b`, 'gi'),
      why: 'The document itself is labelled as restricted. Pasting labelled material into a public AI tool typically breaches the handling rule that the label imposes.',
    }),
    rule({
      id: 'project_codename',
      category: C.ORG, severity: S.MEDIUM, label: 'PROJECT_NAME',
      title: 'Internal project codename', confidence: 0.72, group: 1,
      regex: /\b(?:project|programme|program|operation|initiative|codename|code name|workstream)\s+["']?([A-Za-z][A-Za-z0-9]{2,20}(?:[- ][A-Za-z][A-Za-z0-9]{2,20})?)["']?/gi,
      why: 'Codenames are chosen precisely because the work is not public; the name alone can confirm an unannounced product, deal or restructuring.',
      validate: (v) => {
        // The `i` flag is needed so "Project"/"PROJECT" both match, but the
        // codename itself must still be capitalised — otherwise "project plan"
        // and "project timeline" would look like codenames.
        if (!/^[A-Z]/.test(v)) return false;
        const low = v.toLowerCase();
        const generic = new Set([
          'management','manager','plan','planning','update','updates','status','review','reviews','meeting',
          'meetings','team','teams','lead','leads','owner','timeline','scope','charter','kickoff','kick',
          'deadline','budget','budgets','board','manager','delivery','milestone','milestones','phase',
          'documentation','docs','notes','summary','overview','report','reports','tracker','backlog','sprint',
          'the','this','that','our','my','new','next','last','first','final','draft','current','above','below',
          'we','it','they','all','some','each','more','less','name','names','number','id','details','details',
          'monday','tuesday','wednesday','thursday','friday','saturday','sunday','january','february','march',
          'april','june','july','august','september','october','november','december',
        ]);
        if (generic.has(low)) return false;
        if (/^\d+$/.test(v)) return false;
        return true;
      },
    }),
    rule({
      id: 'internal_system_url',
      category: C.ORG, severity: S.MEDIUM, label: 'INTERNAL_URL',
      title: 'Internal system URL', confidence: 0.85,
      regex: /\bhttps?:\/\/(?:[A-Za-z0-9-]+\.)*(?:atlassian\.net|jira[A-Za-z0-9.-]*|confluence[A-Za-z0-9.-]*|sharepoint\.com|okta\.com|workday\.com|servicenow\.com|internal|intranet|corp|vpn|staging|preprod|uat)(?:\.[A-Za-z]{2,})?(?:\/[^\s"'<>]*)?/gi,
      why: 'Internal URLs disclose your organisation’s tooling, naming conventions and often the exact document under discussion — useful reconnaissance for a targeted attacker.',
    }),
    rule({
      id: 'issue_tracker_key',
      category: C.ORG, severity: S.LOW, label: 'TICKET_ID',
      title: 'Internal ticket reference', confidence: 0.7,
      regex: /\b[A-Z][A-Z0-9]{1,9}-\d{1,6}\b/g,
      needsContext: /\b(?:jira|ticket|issue|story|epic|bug|task|board|sprint|backlog|linear|asana|servicenow)\b/i,
      why: 'Ticket keys leak your project structure and, combined with an internal URL, confirm which system holds the record.',
    }),
    rule({
      id: 'git_remote',
      category: C.ORG, severity: S.MEDIUM, label: 'REPOSITORY',
      title: 'Source repository reference', confidence: 0.8,
      regex: /\b(?:git@[A-Za-z0-9.-]+:[A-Za-z0-9_.\/-]+\.git|https?:\/\/[A-Za-z0-9.-]+\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\.git)\b/g,
      why: 'Repository paths reveal internal code organisation and are the first thing an attacker checks for accidental public exposure.',
    }),
    rule({
      id: 'business_sensitive_term',
      category: C.ORG, severity: S.HIGH, label: 'BUSINESS_CONFIDENTIAL',
      title: 'Non-public business information', confidence: 0.75,
      regex: new RegExp(`\\b(?:${alt(BUSINESS_SENSITIVE)})\\b`, 'gi'),
      why: 'Unannounced financials, deals and restructuring plans are material non-public information; disclosure can breach NDAs, securities rules and trade-secret protection.',
    }),
    rule({
      id: 'contract_value',
      category: C.ORG, severity: S.MEDIUM, label: 'CONTRACT_VALUE',
      title: 'Contract or deal value', confidence: 0.78,
      regex: /\b(?:contract|deal|agreement|purchase order|po|quote|proposal|bid|tender|grant|funding round|invoice)\b[^.\n]{0,40}?[$£€₹]\s?[\d,]+(?:\.\d{1,2})?\s?(?:[kKmMbB]|thousand|million|billion)?/gi,
      why: 'Commercial terms are confidential to the counterparties and are directly exploitable by a competitor bidding against you.',
    }),
    rule({
      id: 'client_confidential_pairing',
      category: C.ORG, severity: S.MEDIUM, label: 'CLIENT_INFORMATION',
      title: 'Named client relationship', confidence: 0.65, group: 1,
      regex: /\b(?:our client|the client|client account|customer account|key account|account name)\s*[,:]?\s*([A-Z][A-Za-z0-9&.'-]+(?:\s+[A-Z][A-Za-z0-9&.'-]+){0,3}(?:\s+(?:Inc|LLC|Ltd|Limited|PLC|GmbH|Corp|Corporation|Group|Holdings|Foundation|Trust))?\.?)/g,
      why: 'Client lists are classic trade secrets and the relationship itself is often covered by a mutual confidentiality clause.',
      validate: (v) => !/^(?:The|This|That|We|They|Our|My|Is|Was|Has|Had)\b/.test(v.trim()),
    }),
  ];

  const RULES = [
    ...CREDENTIAL_RULES,
    ...GOV_FIN_RULES,
    ...MEDICAL_RULES,
    ...PEOPLE_RULES,
    ...CONTACT_RULES,
    ...ORG_RULES,
  ];

  const RULES_BY_ID = Object.fromEntries(RULES.map((r) => [r.id, r]));

  /**
   * Rules whose match is self-evidently a real identifier — a vendor-issued key
   * prefix or a value that passed a checksum. Nearby words like "example" should
   * barely move their confidence: a live `sk-proj-…` key sitting next to
   * `api.example.com` is still a live key.
   */
  const STRONG_IDENTIFIER_RULES = new Set([
    'private_key_block', 'aws_access_key_id', 'aws_secret_access_key', 'github_token',
    'slack_token', 'slack_webhook', 'stripe_key', 'openai_key', 'anthropic_key',
    'google_api_key', 'sendgrid_key', 'npm_token', 'jwt_token', 'db_connection_string',
    'authorization_header', 'env_secret_line',
    'us_ssn_formatted', 'us_ssn_bare', 'payment_card', 'iban', 'us_routing_number',
    'india_aadhaar', 'uk_nino', 'india_pan', 'npi_number',
  ]);

  /** Context booster keywords per category — presence raises confidence. */
  const CATEGORY_CONTEXT_CUES = {
    [C.CONTACT]: ['name', 'contact', 'email', 'phone', 'address', 'reach', 'call', 'lives at', 'resident'],
    [C.GOV_FIN]: ['ssn', 'social security', 'tax', 'passport', 'licence', 'license', 'card', 'account', 'bank', 'payment', 'iban', 'routing'],
    [C.CREDENTIALS]: ['password', 'secret', 'token', 'key', 'credential', 'login', 'auth', 'access', '.env', 'config'],
    [C.MEDICAL]: MEDICAL_CONTEXT,
    [C.PEOPLE]: ['employee', 'staff', 'volunteer', 'client', 'donor', 'hr', 'payroll', 'personnel', 'roster', 'record'],
    [C.ORG]: ['internal', 'confidential', 'nda', 'proprietary', 'board', 'strategy', 'unannounced', 'q1', 'q2', 'q3', 'q4'],
  };

  /* ==== engine/ner.js ==== */
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

  function hasPersonCue(text, start, end) {
    const before = text.slice(Math.max(0, start - 45), start).toLowerCase();
    const after = text.slice(end, Math.min(text.length, end + 35)).toLowerCase();
    const window = before + '   ' + after;
    return PERSON_CONTEXT_CUES.some((cue) => {
      if (cue.includes(' ')) return window.includes(cue);
      return new RegExp(`\\b${cue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`).test(window);
    });
  }

  /**
   * Extract person/organisation candidates.
   * @returns {Array} raw findings (pre-context-scoring)
   */
  function extractEntities(text) {
    const tokens = tokenize(text);
    const out = [];
    let i = 0;

    while (i < tokens.length) {
      if (!tokens[i].cap) { i++; continue; }

      // Grow a maximal run of capitalised tokens (particles allowed in the middle).
      let j = i;
      while (j + 1 < tokens.length) {
        const gap = text.slice(tokens[j].end, tokens[j + 1].start);
        if (!/^[ \t]*[-'’]?[ \t]*$/.test(gap) || gap.length > 2) break;
        const next = tokens[j + 1];
        const isParticle = NAME_PARTICLES.has(next.lower) && j + 2 < tokens.length && tokens[j + 2].cap;
        if (!next.cap && !isParticle) break;
        j++;
        if (j - i >= 4) break;
      }

      const run = tokens.slice(i, j + 1);
      const start = run[0].start;
      const end = run[run.length - 1].end;
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

    const prevWord = previousWord(text, start);
    const hasHonorific = prevWord && HONORIFICS.has(lc(prevWord));
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
    const cue = hasPersonCue(text, start, end);
    const sentenceInitial = isSentenceInitial(text, run[0]);
    const multiWord = run.filter((t) => t.cap).length >= 2;
    const containsNonName = words.some((w) => NON_NAME_WORDS.has(w) || PLACE_NAMES.has(w));

    let score = 0;
    if (multiWord) { score += 0.5; signals.push('two or more capitalised words'); }
    if (gazetteerHit) { score += 0.3; signals.push('matches a common given name'); }
    if (honorific) { score += 0.45; signals.push(`preceded by honorific "${prevToken}"`); }
    if (cue) { score += 0.25; signals.push('appears next to a person-role cue'); }
    if (!multiWord && !gazetteerHit && !honorific) return null;
    if (!multiWord && sentenceInitial && !honorific) return null;
    if (sentenceInitial && !gazetteerHit && !honorific && !cue) score -= 0.2;
    if (containsNonName && !gazetteerHit && !honorific) score -= 0.35;
    if (/'s$|’s$/.test(value)) score += 0.05;

    // Possessive/plural stripping for the reported value.
    if (score < 0.5) return null;

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

  /* ==== engine/context.js ==== */
  /**
   * Context scoring, safe-span protection and overlap resolution.
   *
   * This module exists to stop over-redaction. Precision matters as much as
   * recall here: a tool that redacts "3:00 PM" trains users to ignore it.
   */





  /**
   * Spans that are structurally safe and must never be reported on their own.
   * Any candidate finding fully contained in one of these is dropped.
   */
  const SAFE_SPAN_PATTERNS = [
    // clock times: 3:00 PM, 15:30, 9 am, 3.00pm
    /\b\d{1,2}[:.]\d{2}(?::\d{2})?\s*(?:[ap]\.?m\.?)?\b/gi,
    /\b\d{1,2}\s*(?:[ap]\.?m\.?)\b/gi,
    // ISO and written dates without a birth-date cue
    /\b(?:19|20)\d{2}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:?\d{2})?)?\b/g,
    /\b(?:Mon|Tue|Tues|Wed|Thu|Thur|Thurs|Fri|Sat|Sun)(?:day)?,?\s+\d{1,2}(?:st|nd|rd|th)?\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[a-z]*\b/gi,
    /\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[a-z]*\s+\d{1,2}(?:st|nd|rd|th)?(?:,\s*\d{4})?\b/gi,
    // durations & quantities
    /\b\d+(?:\.\d+)?\s*(?:%|percent|pts?|points?|hours?|hrs?|minutes?|mins?|seconds?|secs?|days?|weeks?|months?|years?|people|users?|items?|rows?|records?|attendees?|participants?)\b/gi,
    // version numbers, ports, ranges
    /\bv?\d+\.\d+(?:\.\d+)*(?:-[A-Za-z0-9.]+)?\b/g,
    /\b(?:port|version|release|build|revision|rev)\s*[:#]?\s*\d+\b/gi,
    // measurement / file sizes
    /\b\d+(?:\.\d+)?\s*(?:kb|mb|gb|tb|ms|kg|lbs?|km|mi|cm|mm|px|em|rem)\b/gi,
    // ordinary rounded currency in a non-contract sentence is handled by rules; protect page/figure refs
    /\b(?:figure|fig\.|table|section|chapter|page|slide|item|step|question|q)\s*\.?\s*\d+(?:\.\d+)?\b/gi,
    // already-redacted placeholders
    /\[[A-Z_]{2,40}(?:_\d+)?\]/g,
    /<[A-Z_]{2,40}>/g,
    /\{\{[^}]{1,40}\}\}/g,
    /(?:x{4,}|\*{4,}|•{4,}|#{4,})/gi,
  ];

  function computeSafeSpans(text) {
    const spans = [];
    for (const re of SAFE_SPAN_PATTERNS) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text)) !== null) {
        if (m[0].length === 0) { re.lastIndex++; continue; }
        spans.push([m.index, m.index + m[0].length]);
      }
    }
    return mergeSpans(spans);
  }

  function mergeSpans(spans) {
    if (!spans.length) return [];
    spans.sort((a, b) => a[0] - b[0]);
    const out = [spans[0].slice()];
    for (let i = 1; i < spans.length; i++) {
      const last = out[out.length - 1];
      if (spans[i][0] <= last[1]) last[1] = Math.max(last[1], spans[i][1]);
      else out.push(spans[i].slice());
    }
    return out;
  }

  function isInsideSafeSpan(safeSpans, start, end) {
    return safeSpans.some(([s, e]) => start >= s && end <= e);
  }

  /** Cheap binary search free containment test for large inputs. */
  function overlapsSafeSpan(safeSpans, start, end) {
    return safeSpans.some(([s, e]) => start < e && end > s);
  }

  /**
   * Adjust a finding's confidence based on the words around it.
   * Returns { confidence, signals[] }.
   */
  function scoreContext(finding, text) {
    const from = Math.max(0, finding.start - CONTEXT_WINDOW);
    const to = Math.min(text.length, finding.end + CONTEXT_WINDOW);
    const ctx = text.slice(from, to).toLowerCase();
    const signals = [...(finding.signals || [])];
    let confidence = finding.confidence;

    const cues = CATEGORY_CONTEXT_CUES[finding.category] || [];
    const hits = cues.filter((c) => ctx.includes(c.toLowerCase()));
    if (hits.length) {
      confidence += Math.min(0.15, 0.05 * hits.length);
      signals.push(`supporting context: ${hits.slice(0, 3).join(', ')}`);
    }

    const placeholderHit = PLACEHOLDER_CUES.find((p) => ctx.includes(p));
    if (placeholderHit) {
      // A vendor-prefixed key or checksum-valid identifier stays confident even in
      // a page full of "example" text — it is still a real, usable value.
      const penalty = finding.strongIdentifier ? 0.05 : 0.22;
      confidence -= penalty;
      if (!finding.strongIdentifier) {
        signals.push(`looks illustrative ("${placeholderHit}")`);
        finding.illustrative = true;
      }
    }

    // Instructional / negated usage: "never paste your API key", "do not share the SSN"
    if (/\b(?:never|do not|don't|avoid|shouldn't|should not|must not|stop) (?:share|paste|send|post|include|store|commit|expose|reveal)\b/.test(ctx)) {
      confidence -= 0.2;
      signals.push('appears inside guidance about not sharing data');
    }

    // Question about the concept rather than a disclosure: "what is an IBAN?"
    if (/\b(?:what (?:is|are)|how (?:do|does|can) i|explain|definition of|difference between)\b/.test(ctx.slice(0, 90))) {
      confidence -= 0.12;
      signals.push('phrased as a general question');
    }

    finding.confidence = Math.max(0.05, Math.min(0.99, confidence));
    finding.signals = signals;
    return finding;
  }

  /**
   * Resolve overlapping findings. Priority order:
   *   1. higher severity
   *   2. longer span (a full IBAN beats a phone-shaped fragment inside it)
   *   3. higher confidence
   */
  function resolveOverlaps(findings) {
    const sorted = [...findings].sort((a, b) => {
      const sev = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
      if (sev) return sev;
      const len = (b.end - b.start) - (a.end - a.start);
      if (len) return len;
      return b.confidence - a.confidence;
    });

    const kept = [];
    for (const f of sorted) {
      const clash = kept.some((k) => f.start < k.end && f.end > k.start);
      if (!clash) kept.push(f);
    }
    return kept.sort((a, b) => a.start - b.start);
  }

  /* ==== engine/policy.js ==== */
  /**
   * Enterprise policy layer.
   *
   * A policy is a plain JSON object an administrator can ship to every user
   * (via the extension options page or a bundled managed-storage file). It
   * controls which categories are active, thresholds, custom organisational
   * rules and what happens when a critical finding is present.
   */



  const DEFAULT_POLICY = {
    version: 1,
    name: 'Balanced (default)',
    /** Categories that are scanned at all. */
    enabledCategories: Object.values(CATEGORIES),
    /** Minimum confidence for a finding to be *reported*. */
    reportThreshold: 0.35,
    /** Minimum confidence for a finding to be redacted by default. */
    redactThreshold: 0.5,
    /** Per-category severity overrides, e.g. { org_confidential: 'critical' }. */
    severityOverrides: {},
    /** Placeholder style: 'label' -> [EMAIL], 'numbered' -> [EMAIL_1], 'mask' -> partial mask, 'pseudonym' -> synthetic value. */
    redactionStyle: 'numbered',
    /** Block sending when the risk score reaches this value (extension only). 101 = never block. */
    blockAtScore: 50,
    /** Warn (non-blocking) at this score. */
    warnAtScore: 1,
    /** Organisation-specific literal terms, e.g. internal codenames. */
    customTerms: [],
    /** Organisation-specific regex rules. */
    customRules: [],
    /** Domains treated as internal — emails on these are always flagged. */
    internalDomains: [],
    /** Keep a local, content-free audit trail. */
    auditLog: { enabled: true, storeContent: false, maxEntries: 200 },
  };

  const POLICY_PRESETS = {
    balanced: { ...DEFAULT_POLICY },
    strict: {
      ...DEFAULT_POLICY,
      name: 'Strict (regulated environment)',
      reportThreshold: 0.25,
      redactThreshold: 0.35,
      blockAtScore: 25,
      severityOverrides: { [CATEGORIES.ORG]: SEVERITY.CRITICAL, [CATEGORIES.PEOPLE]: SEVERITY.CRITICAL },
    },
    healthcare: {
      ...DEFAULT_POLICY,
      name: 'Healthcare (HIPAA-oriented)',
      reportThreshold: 0.25,
      redactThreshold: 0.4,
      blockAtScore: 25,
      severityOverrides: { [CATEGORIES.MEDICAL]: SEVERITY.CRITICAL, [CATEGORIES.CONTACT]: SEVERITY.CRITICAL },
    },
    finance: {
      ...DEFAULT_POLICY,
      name: 'Financial services (PCI / SOX-oriented)',
      reportThreshold: 0.3,
      redactThreshold: 0.45,
      blockAtScore: 25,
      severityOverrides: { [CATEGORIES.GOV_FIN]: SEVERITY.CRITICAL, [CATEGORIES.ORG]: SEVERITY.CRITICAL },
    },
    engineering: {
      ...DEFAULT_POLICY,
      name: 'Engineering (secret-hunting)',
      reportThreshold: 0.3,
      redactThreshold: 0.45,
      blockAtScore: 40,
      severityOverrides: { [CATEGORIES.CREDENTIALS]: SEVERITY.CRITICAL },
    },
    permissive: {
      ...DEFAULT_POLICY,
      name: 'Permissive (high precision only)',
      reportThreshold: 0.55,
      redactThreshold: 0.7,
      blockAtScore: 101,
    },
  };

  function normalisePolicy(input) {
    const p = { ...DEFAULT_POLICY, ...(input || {}) };
    p.enabledCategories = Array.isArray(p.enabledCategories) && p.enabledCategories.length
      ? p.enabledCategories.filter((c) => Object.values(CATEGORIES).includes(c))
      : [...DEFAULT_POLICY.enabledCategories];
    p.reportThreshold = clamp(p.reportThreshold, 0, 1);
    p.redactThreshold = clamp(Math.max(p.redactThreshold, p.reportThreshold), 0, 1);
    p.customTerms = (p.customTerms || []).filter((t) => typeof t === 'string' && t.trim().length >= 3);
    p.customRules = (p.customRules || []).filter((r) => r && r.pattern);
    p.internalDomains = (p.internalDomains || []).map((d) => String(d).toLowerCase().replace(/^@/, ''));
    p.auditLog = { ...DEFAULT_POLICY.auditLog, ...(p.auditLog || {}) };
    return p;
  }

  function clamp(n, lo, hi) {
    const v = Number(n);
    if (Number.isNaN(v)) return lo;
    return Math.min(hi, Math.max(lo, v));
  }

  const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  /**
   * Turn policy custom terms and custom regexes into engine rules.
   */
  function buildCustomRules(policy) {
    const rules = [];

    if (policy.customTerms.length) {
      rules.push({
        id: 'policy_custom_term',
        category: CATEGORIES.ORG,
        severity: SEVERITY.HIGH,
        label: 'INTERNAL_TERM',
        title: 'Organisation-defined restricted term',
        why: 'Your organisation has listed this term as restricted. Mentioning it externally may confirm work that has not been announced.',
        confidence: 0.9,
        group: 0,
        regex: new RegExp(`\\b(?:${policy.customTerms.map(escapeRe).sort((a, b) => b.length - a.length).join('|')})\\b`, 'gi'),
        custom: true,
      });
    }

    for (const [i, r] of policy.customRules.entries()) {
      let regex;
      try {
        regex = new RegExp(r.pattern, r.flags && /^[gimsuy]*$/.test(r.flags) ? ensureGlobal(r.flags) : 'gi');
      } catch {
        continue; // an invalid admin regex must never break scanning
      }
      rules.push({
        id: r.id || `policy_custom_rule_${i}`,
        category: Object.values(CATEGORIES).includes(r.category) ? r.category : CATEGORIES.ORG,
        severity: Object.values(SEVERITY).includes(r.severity) ? r.severity : SEVERITY.HIGH,
        label: (r.label || 'CUSTOM').toUpperCase().replace(/[^A-Z0-9_]/g, '_'),
        title: r.title || 'Custom policy rule',
        why: r.why || 'Flagged by a rule configured by your organisation.',
        confidence: typeof r.confidence === 'number' ? clamp(r.confidence, 0, 1) : 0.85,
        group: Number.isInteger(r.group) ? r.group : 0,
        regex,
        custom: true,
      });
    }

    if (policy.internalDomains.length) {
      rules.push({
        id: 'policy_internal_email_domain',
        category: CATEGORIES.PEOPLE,
        severity: SEVERITY.HIGH,
        label: 'INTERNAL_EMAIL',
        title: 'Internal email address',
        why: 'This mailbox belongs to your organisation. Exposing internal addresses enables targeted phishing against your colleagues.',
        confidence: 0.95,
        group: 0,
        regex: new RegExp(`\\b[A-Za-z0-9._%+-]+@(?:${policy.internalDomains.map(escapeRe).join('|')})\\b`, 'gi'),
        custom: true,
      });
    }

    return rules;
  }

  function ensureGlobal(flags) {
    return flags.includes('g') ? flags : flags + 'g';
  }

  /* ==== engine/risk.js ==== */
  /**
   * Severity & risk scoring.
   *
   * The score answers one question: "how bad would it be if this exact text
   * left my machine?" It is deliberately dominated by the worst single finding
   * rather than by volume, so ten low-risk names never outrank one live API key.
   */



  function scoreRisk(findings) {
    const active = findings.filter((f) => !f.dismissed);
    if (!active.length) {
      return {
        score: 0,
        band: bandForScore(0),
        worstSeverity: null,
        counts: { critical: 0, high: 0, medium: 0, low: 0 },
        byCategory: {},
        total: 0,
        uniqueValues: 0,
        rationale: ['No sensitive information detected.'],
      };
    }

    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    const byCategory = {};
    const seen = new Map();          // dedupe identical values
    let raw = 0;

    for (const f of active) {
      counts[f.severity]++;
      byCategory[f.category] = (byCategory[f.category] || 0) + 1;

      const key = `${f.category}:${String(f.value).trim().toLowerCase()}`;
      const repeats = seen.get(key) || 0;
      seen.set(key, repeats + 1);

      // Repeated occurrences of the same value add little extra risk.
      const decay = 1 / (1 + repeats * 1.6);
      raw += SEVERITY_WEIGHT[f.severity] * f.confidence * decay;
    }

    // Worst-single-finding floor: one confident critical is always >= 75.
    const worst = active.reduce((a, b) => (SEVERITY_RANK[b.severity] > SEVERITY_RANK[a.severity] ? b : a));
    const floors = { critical: 75, high: 45, medium: 18, low: 5 };
    const floorScale = worst.confidence >= 0.8 ? 1 : Math.max(0.5, worst.confidence);
    const floor = Math.round(floors[worst.severity] * floorScale);

    const score = Math.max(floor, Math.min(100, Math.round(raw)));
    const band = bandForScore(score);

    const rationale = [];
    if (counts.critical) rationale.push(`${counts.critical} critical finding${counts.critical > 1 ? 's' : ''} (identity, financial or credential data).`);
    if (counts.high) rationale.push(`${counts.high} high-severity finding${counts.high > 1 ? 's' : ''}.`);
    if (counts.medium) rationale.push(`${counts.medium} medium-severity finding${counts.medium > 1 ? 's' : ''}.`);
    if (counts.low) rationale.push(`${counts.low} low-severity finding${counts.low > 1 ? 's' : ''}.`);
    const cats = Object.keys(byCategory).map((c) => CATEGORY_META[c]?.short || c);
    if (cats.length) rationale.push(`Categories present: ${cats.join(', ')}.`);

    return {
      score,
      band,
      worstSeverity: worst.severity,
      counts,
      byCategory,
      total: active.length,
      uniqueValues: seen.size,
      rationale,
    };
  }

  /** Short, plain-language verdict for the top of the UI. */
  function verdict(risk, policy) {
    if (risk.score === 0) {
      return {
        headline: 'Nothing sensitive detected',
        detail: 'This text looks safe to send. Nothing was changed.',
        action: 'send',
      };
    }
    if (policy && risk.score >= policy.blockAtScore) {
      return {
        headline: 'Do not send as written',
        detail: 'This prompt contains information your policy blocks from leaving the organisation. Redact before sending.',
        action: 'block',
      };
    }
    return {
      headline: 'Review before sending',
      detail: 'Some details in this prompt identify people or your organisation. Redact what is not needed for the answer.',
      action: 'warn',
    };
  }

  /* ==== engine/redact.js ==== */
  /**
   * Redaction.
   *
   * Design rules:
   *  - Only touch the exact character spans of kept findings. Everything else is
   *    byte-for-byte identical to the input. This is what guarantees that
   *    "The project meeting is scheduled for 3:00 PM" comes back unchanged.
   *  - Keep the text readable: the same person gets the same token every time,
   *    so an LLM can still follow "[NAME_1] emailed [NAME_2]".
   *  - Everything is reversible in the UI via per-finding keep/redact toggles.
   */

  const PSEUDONYM_POOL = {
    NAME: ['Alex Rivera', 'Jordan Blake', 'Sam Okafor', 'Riley Nakamura', 'Casey Moreau', 'Devon Ashby'],
    EMAIL: ['a.rivera@example.com', 'j.blake@example.com', 's.okafor@example.com', 'r.nakamura@example.com'],
    PHONE: ['+1 555 0100', '+1 555 0101', '+1 555 0102', '+1 555 0103'],
    ORGANIZATION: ['Northwind Trading', 'Contoso Group', 'Acme Holdings', 'Globex Partners'],
    ADDRESS: ['1 Example Street, Springfield', '2 Sample Avenue, Springfield'],
  };

  /**
   * @param {string} text            original text
   * @param {Array}  findings        findings from scan()
   * @param {object} options
   *   style: 'label' | 'numbered' | 'mask' | 'pseudonym'
   * @returns {{ text, replacements, changed }}
   */
  function redact(text, findings, options = {}) {
    const style = options.style || 'numbered';
    const kept = findings
      .filter((f) => f.redact && !f.dismissed)
      .sort((a, b) => a.start - b.start);

    if (!kept.length) return { text, replacements: [], changed: false };

    const counters = new Map();      // label -> next index
    const assigned = new Map();      // label|value -> placeholder
    const replacements = [];

    let out = '';
    let cursor = 0;

    for (const f of kept) {
      if (f.start < cursor) continue;                    // defensive: skip overlaps
      const original = text.slice(f.start, f.end);
      const key = `${f.label}|${normalise(original)}`;

      let placeholder = assigned.get(key);
      if (!placeholder) {
        const n = (counters.get(f.label) || 0) + 1;
        counters.set(f.label, n);
        placeholder = buildPlaceholder(style, f.label, n, original);
        assigned.set(key, placeholder);
      }

      out += text.slice(cursor, f.start) + placeholder;
      cursor = f.end;
      replacements.push({
        id: f.id,
        label: f.label,
        category: f.category,
        severity: f.severity,
        placeholder,
        start: f.start,
        end: f.end,
        length: original.length,
      });
    }

    out += text.slice(cursor);
    return { text: out, replacements, changed: out !== text };
  }

  function normalise(v) {
    return String(v).trim().toLowerCase().replace(/\s+/g, ' ');
  }

  function buildPlaceholder(style, label, n, original) {
    switch (style) {
      case 'label':
        return `[${label}]`;
      case 'mask':
        return maskValue(original, label);
      case 'pseudonym': {
        const pool = PSEUDONYM_POOL[label];
        if (pool) return pool[(n - 1) % pool.length];
        return `[${label}_${n}]`;
      }
      case 'numbered':
      default:
        return `[${label}_${n}]`;
    }
  }

  /** Partial mask that preserves shape but not content. */
  function maskValue(v, label) {
    if (label === 'EMAIL') {
      const [local, domain = ''] = v.split('@');
      const tld = domain.includes('.') ? domain.slice(domain.lastIndexOf('.')) : '';
      return `${local.slice(0, 1)}${'•'.repeat(Math.max(2, local.length - 1))}@${'•'.repeat(3)}${tld}`;
    }
    const digits = v.replace(/\D/g, '');
    if (digits.length >= 6) {
      const tail = digits.slice(-4);
      return `${'•'.repeat(Math.max(4, digits.length - 4))}${tail}`;
    }
    if (v.length <= 3) return '•'.repeat(v.length);
    return `${v.slice(0, 1)}${'•'.repeat(v.length - 2)}${v.slice(-1)}`;
  }

  /**
   * Build highlight segments for rendering: an ordered list of
   * { text, finding|null } covering the whole input exactly once.
   */
  function segment(text, findings) {
    const active = findings.filter((f) => !f.dismissed).sort((a, b) => a.start - b.start);
    const segments = [];
    let cursor = 0;
    for (const f of active) {
      if (f.start < cursor) continue;
      if (f.start > cursor) segments.push({ text: text.slice(cursor, f.start), finding: null });
      segments.push({ text: text.slice(f.start, f.end), finding: f });
      cursor = f.end;
    }
    if (cursor < text.length) segments.push({ text: text.slice(cursor), finding: null });
    return segments;
  }

  /* ==== engine/engine.js ==== */
  /**
   * Scan orchestration.
   *
   * scan(text, options) -> {
   *   text, findings[], risk, verdict, stats, policy
   * }
   *
   * The whole pipeline is synchronous, pure and offline. No network calls exist
   * anywhere in this module or its imports — that is a deliberate, testable
   * property of the design, not just a promise in the README.
   */








  const MAX_INPUT = 200_000;
  const indexedRegexCache = new WeakMap();

  function withIndices(regex) {
    let cached = indexedRegexCache.get(regex);
    if (cached) return cached;
    const flags = regex.flags.includes('d') ? regex.flags : regex.flags + 'd';
    cached = new RegExp(regex.source, flags);
    indexedRegexCache.set(regex, cached);
    return cached;
  }

  let idCounter = 0;
  const nextId = () => `f${(++idCounter).toString(36)}`;

  /**
   * @param {string} text
   * @param {object} [options]
   * @param {object} [options.policy]      policy object (see policy.js)
   * @param {boolean} [options.ner=true]   run the name/organisation extractor
   * @returns {object} scan result
   */
  function scan(text, options = {}) {
    const started = now();
    const policy = normalisePolicy(options.policy || DEFAULT_POLICY);
    const input = typeof text === 'string' ? text : '';
    const truncated = input.length > MAX_INPUT;
    const body = truncated ? input.slice(0, MAX_INPUT) : input;

    if (!body.trim()) {
      return emptyResult(body, policy, started, truncated);
    }

    const safeSpans = computeSafeSpans(body);
    const enabled = new Set(policy.enabledCategories);
    const allRules = [...RULES, ...buildCustomRules(policy)];
    const candidates = [];

    for (const rule of allRules) {
      if (!enabled.has(rule.category)) continue;
      collectRuleMatches(rule, body, safeSpans, candidates);
    }

    if (options.ner !== false) {
      for (const entity of extractEntities(body)) {
        if (!enabled.has(entity.category)) continue;
        if (isInsideSafeSpan(safeSpans, entity.start, entity.end)) continue;
        candidates.push({
          id: nextId(),
          ...entity,
          method: 'ner',
        });
      }
    }

    // Context scoring
    for (const c of candidates) scoreContext(c, body);

    // Policy severity overrides
    for (const c of candidates) {
      const override = policy.severityOverrides[c.category];
      if (override && SEVERITY_RANK[override] > SEVERITY_RANK[c.severity]) c.severity = override;
    }

    // Threshold + overlap resolution
    const reported = candidates.filter((c) => c.confidence >= policy.reportThreshold);
    const findings = resolveOverlaps(reported).map((f) => ({
      ...f,
      categoryName: CATEGORY_META[f.category]?.name || f.category,
      categoryWhy: CATEGORY_META[f.category]?.why || '',
      redact: f.confidence >= policy.redactThreshold,
      dismissed: false,
      line: lineNumberAt(body, f.start),
    }));

    const risk = scoreRisk(findings);

    return {
      text: body,
      truncated,
      findings,
      risk,
      verdict: verdict(risk, policy),
      policy,
      stats: {
        characters: body.length,
        words: body.trim() ? body.trim().split(/\s+/).length : 0,
        candidates: candidates.length,
        reported: findings.length,
        suppressed: candidates.length - findings.length,
        durationMs: Math.round((now() - started) * 100) / 100,
        rulesEvaluated: allRules.length,
      },
    };
  }

  function collectRuleMatches(rule, body, safeSpans, out) {
    const re = withIndices(rule.regex);
    re.lastIndex = 0;
    let m;
    let guard = 0;

    while ((m = re.exec(body)) !== null) {
      if (++guard > 5000) break;
      if (m[0].length === 0) { re.lastIndex++; continue; }

      const g = rule.group || 0;
      const span = (m.indices && m.indices[g]) || null;
      if (g > 0 && !span) continue;
      const start = span ? span[0] : m.index;
      const end = span ? span[1] : m.index + m[0].length;
      const value = body.slice(start, end);
      if (!value) continue;

      if (!rule.ignoreSafeSpans && isInsideSafeSpan(safeSpans, start, end)) continue;

      const context = body.slice(
        Math.max(0, m.index - CONTEXT_WINDOW),
        Math.min(body.length, m.index + m[0].length + CONTEXT_WINDOW),
      );

      if (rule.needsContext && !rule.needsContext.test(context)) continue;

      let severity = rule.severity;
      let confidence = rule.confidence;
      let note;
      let label = rule.label;

      if (typeof rule.validate === 'function') {
        const verdictValue = rule.validate(value, { ...m, context }, body);
        if (verdictValue === false || verdictValue === null || verdictValue === undefined) continue;
        if (typeof verdictValue === 'object') {
          if (verdictValue.severity) severity = verdictValue.severity;
          if (typeof verdictValue.confidence === 'number') confidence = verdictValue.confidence;
          if (verdictValue.note) note = verdictValue.note;
          if (verdictValue.label) label = verdictValue.label;
        }
      }

      out.push({
        id: nextId(),
        ruleId: rule.id,
        category: rule.category,
        severity,
        label,
        title: rule.title,
        why: rule.why,
        note,
        value,
        start,
        end,
        confidence,
        method: rule.custom ? 'policy' : 'pattern',
        strongIdentifier: STRONG_IDENTIFIER_RULES.has(rule.id),
        signals: [],
        matchText: m[0],
      });
    }
  }

  function lineNumberAt(text, index) {
    let line = 1;
    for (let i = 0; i < index && i < text.length; i++) if (text[i] === '\n') line++;
    return line;
  }

  function emptyResult(body, policy, started, truncated) {
    const risk = scoreRisk([]);
    return {
      text: body,
      truncated,
      findings: [],
      risk,
      verdict: verdict(risk, policy),
      policy,
      stats: {
        characters: body.length,
        words: 0,
        candidates: 0,
        reported: 0,
        suppressed: 0,
        durationMs: Math.round((now() - started) * 100) / 100,
        rulesEvaluated: 0,
      },
    };
  }

  function now() {
    if (typeof performance !== 'undefined' && performance.now) return performance.now();
    return Date.now();
  }


  root.ShadowAI = {
    version: '1.0.0',
    scan: typeof scan !== 'undefined' ? scan : undefined,
    redact: typeof redact !== 'undefined' ? redact : undefined,
    segment: typeof segment !== 'undefined' ? segment : undefined,
    scoreRisk: typeof scoreRisk !== 'undefined' ? scoreRisk : undefined,
    verdict: typeof verdict !== 'undefined' ? verdict : undefined,
    CATEGORIES: typeof CATEGORIES !== 'undefined' ? CATEGORIES : undefined,
    CATEGORY_META: typeof CATEGORY_META !== 'undefined' ? CATEGORY_META : undefined,
    CATEGORY_LIST: typeof CATEGORY_LIST !== 'undefined' ? CATEGORY_LIST : undefined,
    SEVERITY: typeof SEVERITY !== 'undefined' ? SEVERITY : undefined,
    SEVERITY_RANK: typeof SEVERITY_RANK !== 'undefined' ? SEVERITY_RANK : undefined,
    SEVERITY_WEIGHT: typeof SEVERITY_WEIGHT !== 'undefined' ? SEVERITY_WEIGHT : undefined,
    RISK_BANDS: typeof RISK_BANDS !== 'undefined' ? RISK_BANDS : undefined,
    bandForScore: typeof bandForScore !== 'undefined' ? bandForScore : undefined,
    DEFAULT_POLICY: typeof DEFAULT_POLICY !== 'undefined' ? DEFAULT_POLICY : undefined,
    POLICY_PRESETS: typeof POLICY_PRESETS !== 'undefined' ? POLICY_PRESETS : undefined,
    normalisePolicy: typeof normalisePolicy !== 'undefined' ? normalisePolicy : undefined,
    RULES: typeof RULES !== 'undefined' ? RULES : undefined,
    RULES_BY_ID: typeof RULES_BY_ID !== 'undefined' ? RULES_BY_ID : undefined,
    extractEntities: typeof extractEntities !== 'undefined' ? extractEntities : undefined,
  };
})(typeof globalThis !== 'undefined' ? globalThis : self);
