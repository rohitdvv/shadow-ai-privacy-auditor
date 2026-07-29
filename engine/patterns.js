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

import { CATEGORIES as C, SEVERITY as S } from './constants.js';
import {
  luhn, cardBrand, ibanValid, abaRoutingValid, verhoeffValid, npiValid,
  ssnStructurallyValid, looksLikeSecret, isKnownTestValue, isPrivateIPv4, isValidIPv4,
  shannonEntropy, charClasses,
} from './validators.js';
import {
  MEDICAL_CONDITIONS, MEDICATIONS, MEDICAL_CONTEXT, IMMIGRATION_TERMS,
  PROTECTED_ATTRIBUTES, CONFIDENTIALITY_MARKERS, BUSINESS_SENSITIVE, COMMON_WORDS,
} from './gazetteers.js';

export const CONTEXT_WINDOW = 80;

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

export const RULES = [
  ...CREDENTIAL_RULES,
  ...GOV_FIN_RULES,
  ...MEDICAL_RULES,
  ...PEOPLE_RULES,
  ...CONTACT_RULES,
  ...ORG_RULES,
];

export const RULES_BY_ID = Object.fromEntries(RULES.map((r) => [r.id, r]));

/**
 * Rules whose match is self-evidently a real identifier — a vendor-issued key
 * prefix or a value that passed a checksum. Nearby words like "example" should
 * barely move their confidence: a live `sk-proj-…` key sitting next to
 * `api.example.com` is still a live key.
 */
export const STRONG_IDENTIFIER_RULES = new Set([
  'private_key_block', 'aws_access_key_id', 'aws_secret_access_key', 'github_token',
  'slack_token', 'slack_webhook', 'stripe_key', 'openai_key', 'anthropic_key',
  'google_api_key', 'sendgrid_key', 'npm_token', 'jwt_token', 'db_connection_string',
  'authorization_header', 'env_secret_line',
  'us_ssn_formatted', 'us_ssn_bare', 'payment_card', 'iban', 'us_routing_number',
  'india_aadhaar', 'uk_nino', 'india_pan', 'npi_number',
]);

/** Context booster keywords per category — presence raises confidence. */
export const CATEGORY_CONTEXT_CUES = {
  [C.CONTACT]: ['name', 'contact', 'email', 'phone', 'address', 'reach', 'call', 'lives at', 'resident'],
  [C.GOV_FIN]: ['ssn', 'social security', 'tax', 'passport', 'licence', 'license', 'card', 'account', 'bank', 'payment', 'iban', 'routing'],
  [C.CREDENTIALS]: ['password', 'secret', 'token', 'key', 'credential', 'login', 'auth', 'access', '.env', 'config'],
  [C.MEDICAL]: MEDICAL_CONTEXT,
  [C.PEOPLE]: ['employee', 'staff', 'volunteer', 'client', 'donor', 'hr', 'payroll', 'personnel', 'roster', 'record'],
  [C.ORG]: ['internal', 'confidential', 'nda', 'proprietary', 'board', 'strategy', 'unannounced', 'q1', 'q2', 'q3', 'q4'],
};
