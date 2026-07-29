/**
 * Shadow AI Privacy Auditor — category & severity constants.
 * Zero dependencies. Shared by the web app, the browser extension and the test runner.
 */

export const CATEGORIES = {
  CONTACT: 'contact',
  GOV_FIN: 'government_financial',
  CREDENTIALS: 'credentials',
  MEDICAL: 'medical_sensitive',
  PEOPLE: 'people_records',
  ORG: 'org_confidential',
};

export const SEVERITY = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
};

/** Points contributed to the 0-100 risk score by a single max-confidence finding. */
export const SEVERITY_WEIGHT = {
  critical: 45,
  high: 22,
  medium: 9,
  low: 3,
};

export const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

export const CATEGORY_META = {
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

export const CATEGORY_LIST = Object.values(CATEGORY_META).sort((a, b) => a.order - b.order);

/** Risk bands for the overall 0-100 score. */
export const RISK_BANDS = [
  { min: 0, max: 0, level: 'safe', label: 'Safe to send', color: '#15803d' },
  { min: 1, max: 24, level: 'low', label: 'Low risk', color: '#65a30d' },
  { min: 25, max: 49, level: 'moderate', label: 'Moderate risk', color: '#ca8a04' },
  { min: 50, max: 74, level: 'high', label: 'High risk', color: '#ea580c' },
  { min: 75, max: 100, level: 'critical', label: 'Critical — do not send', color: '#b91c1c' },
];

export function bandForScore(score) {
  return RISK_BANDS.find((b) => score >= b.min && score <= b.max) || RISK_BANDS[0];
}
