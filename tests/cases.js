/**
 * Fictional test corpus.
 *
 * RESPONSIBLE DATA USE: every value below is invented for this project. Names,
 * organisations, addresses and domains are fictional (example.com / .invalid /
 * made-up charities). Identifier values were generated to satisfy the relevant
 * checksum (Luhn, mod-97, Verhoeff, ABA) so the validators can be exercised —
 * they are not issued to anyone. Credentials use the vendor-published
 * documentation/test values or randomly generated strings.
 *
 * Case shape:
 *   id           stable identifier used in the results table
 *   name         short description
 *   kind         'risky' | 'safe' | 'edge'
 *   text         the prompt a user might paste into ChatGPT
 *   expect:
 *     categories   categories that MUST appear in the findings
 *     mustFlag     substrings that MUST be covered by a finding
 *     mustNotFlag  substrings that must NOT be covered by any finding
 *     unchanged    true => default redaction must return the input verbatim
 *     maxSeverity  highest severity allowed (used for "this is only a test value")
 *     minScore/maxScore  bounds on the risk score
 */

export const CASES = [
  /* ---------------------------------------------------------------- */
  /* SAFE — the anti-over-redaction suite                              */
  /* ---------------------------------------------------------------- */
  {
    id: 'S-01',
    name: 'Meeting time (the brief’s canonical safe sentence)',
    kind: 'safe',
    text: 'The project meeting is scheduled for 3:00 PM.',
    expect: { categories: [], mustNotFlag: ['3:00 PM', 'project meeting'], unchanged: true, maxScore: 0 },
  },
  {
    id: 'S-02',
    name: 'Generic writing request',
    kind: 'safe',
    text: 'Can you rewrite this paragraph so it is more concise and a little friendlier in tone?',
    expect: { categories: [], unchanged: true, maxScore: 0 },
  },
  {
    id: 'S-03',
    name: 'Financial concept question (no personal data)',
    kind: 'safe',
    text: 'What is the difference between a Roth IRA and a traditional 401(k) for someone in their thirties?',
    expect: { categories: [], mustNotFlag: ['Roth IRA'], unchanged: true, maxScore: 0 },
  },
  {
    id: 'S-04',
    name: 'Agenda with times, dates and room numbers',
    kind: 'safe',
    text: 'The project meeting is scheduled for 3:00 PM on Tuesday, 14 March, in Room 402. Please review the agenda beforehand.',
    expect: { categories: [], mustNotFlag: ['3:00 PM', 'Room 402', '14 March'], unchanged: true, maxScore: 0 },
  },
  {
    id: 'S-05',
    name: 'Engineering metrics with numbers and versions',
    kind: 'safe',
    text: 'Increase the batch size from 32 to 64, upgrade to v2.14.1, and rerun for 10 epochs. Accuracy improved 3.2% to 91.4% on the validation split.',
    expect: { categories: [], mustNotFlag: ['v2.14.1', '91.4%'], unchanged: true, maxScore: 0 },
  },
  {
    id: 'S-06',
    name: 'Security advice that mentions credentials without containing any',
    kind: 'safe',
    text: 'Remember that your password is important, but never share your password with anyone, and do not paste your API key into a chat window.',
    expect: { categories: [], mustNotFlag: ['password is important', 'API key'], unchanged: true, maxScore: 0 },
  },
  {
    id: 'S-07',
    name: 'Generic coding request',
    kind: 'safe',
    text: 'Write a Python function that reverses a linked list without using recursion, and explain the time complexity.',
    expect: { categories: [], mustNotFlag: ['Python'], unchanged: true, maxScore: 0 },
  },
  {
    id: 'S-08',
    name: 'Process question that uses business vocabulary',
    kind: 'safe',
    text: 'Summarise the main risks in a typical vendor renewal process and suggest three questions to ask before signing.',
    expect: { categories: [], unchanged: true, maxScore: 0 },
  },
  {
    id: 'S-09',
    name: 'Educational medical question (concept, not a patient)',
    kind: 'safe',
    text: 'What is type 2 diabetes and how is it usually treated? Explain it for a general audience.',
    expect: { unchanged: true, maxSeverity: 'low', maxScore: 10 },
  },
  {
    id: 'S-10',
    name: 'Placeholders already redacted',
    kind: 'safe',
    text: 'Draft a reply using this template: "Dear [NAME_1], your request reference [CASE_ID] has been received."',
    expect: { categories: [], mustNotFlag: ['[NAME_1]', '[CASE_ID]'], unchanged: true, maxScore: 0 },
  },

  /* ---------------------------------------------------------------- */
  /* CATEGORY 1 — names & contact information                          */
  /* ---------------------------------------------------------------- */
  {
    id: 'R-01',
    name: 'Full contact block',
    kind: 'risky',
    text: 'Hi, my name is Priya Raghavan and you can reach me at priya.raghavan@northwind-relief.invalid or on +1 (415) 555-0142. I live at 482 Sycamore Lane, Apt 3B, Portland, OR 97205.',
    expect: {
      categories: ['contact'],
      mustFlag: ['Priya Raghavan', 'priya.raghavan@northwind-relief.invalid', '+1 (415) 555-0142', '482 Sycamore Lane'],
      minScore: 45,
    },
  },
  {
    id: 'R-02',
    name: 'Name behind an honorific with no other identifiers',
    kind: 'risky',
    text: 'Please draft a short thank-you note to Dr. Eleanor Vance for chairing the safeguarding panel last week.',
    expect: { categories: ['contact'], mustFlag: ['Eleanor Vance'] },
  },
  {
    id: 'R-03',
    name: 'Name recognised from a role cue rather than a gazetteer',
    kind: 'risky',
    text: 'Forward this summary to my manager, Chidi Okonkwo, and copy the volunteer coordinator.',
    expect: { categories: ['contact'], mustFlag: ['Chidi Okonkwo'] },
  },
  {
    id: 'R-04',
    name: 'Date of birth plus profile URL',
    kind: 'risky',
    text: 'Applicant details — DOB: 1988-04-17, LinkedIn: https://www.linkedin.com/in/fictional-applicant-8821.',
    expect: {
      categories: ['contact'],
      mustFlag: ['1988-04-17', 'linkedin.com/in/fictional-applicant-8821'],
    },
  },

  /* ---------------------------------------------------------------- */
  /* CATEGORY 2 — government & financial identifiers                   */
  /* ---------------------------------------------------------------- */
  {
    id: 'R-05',
    name: 'Loan application with SSN and payment card',
    kind: 'risky',
    text: 'For the loan file: SSN 274-98-1163, card number 4539 5781 0033 8448, expiry 08/27, CVV 921. Applicant is Marcus Chen.',
    expect: {
      categories: ['government_financial', 'contact'],
      mustFlag: ['274-98-1163', '4539 5781 0033 8448', '921', 'Marcus Chen'],
      minScore: 75,
    },
  },
  {
    id: 'R-06',
    name: 'International wire instructions',
    kind: 'risky',
    text: 'Please wire the grant to IBAN GB33BUKB20201555555555, SWIFT BUKBGB22, routing number 021000021.',
    expect: {
      categories: ['government_financial'],
      mustFlag: ['GB33BUKB20201555555555', '021000021'],
      minScore: 60,
    },
  },
  {
    id: 'R-07',
    name: 'Indian national identifiers',
    kind: 'risky',
    text: 'KYC pack attached: Aadhaar 3829 1047 5627 and PAN ABCPD1234K for the beneficiary.',
    expect: { categories: ['government_financial'], mustFlag: ['3829 1047 5627', 'ABCPD1234K'] },
  },
  {
    id: 'R-08',
    name: 'UK national insurance number and passport',
    kind: 'risky',
    text: 'Right-to-work check: National Insurance number SK 82 91 47 C, passport number 512345678.',
    expect: { categories: ['government_financial'], mustFlag: ['SK 82 91 47 C', '512345678'] },
  },
  {
    id: 'R-09',
    name: 'Well-known sandbox test card (must not be treated as critical)',
    kind: 'edge',
    text: 'Use the sandbox test card 4111 1111 1111 1111 with any future expiry to reproduce the checkout bug.',
    expect: { categories: ['government_financial'], mustFlag: ['4111 1111 1111 1111'], maxSeverity: 'low', maxScore: 24 },
  },

  /* ---------------------------------------------------------------- */
  /* CATEGORY 3 — credentials                                          */
  /* ---------------------------------------------------------------- */
  {
    id: 'R-10',
    name: 'Pasted .env file',
    kind: 'risky',
    text: [
      'My deploy keeps failing, here is my .env — what is wrong?',
      'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
      'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      'GITHUB_TOKEN=ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8',
      'DATABASE_URL=postgres://svc_admin:Hunter2-Rotate-Me@db.internal.invalid:5432/prod',
    ].join('\n'),
    expect: {
      categories: ['credentials'],
      mustFlag: [
        'AKIAIOSFODNN7EXAMPLE',
        'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        'ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8',
        'postgres://svc_admin:Hunter2-Rotate-Me@db.internal.invalid:5432/prod',
      ],
      minScore: 75,
    },
  },
  {
    id: 'R-11',
    name: 'Inline password and bearer token',
    kind: 'risky',
    text: 'The admin login is service.desk with password Autumn!Ledger42 and the request used Authorization: Bearer 8f2c91ae4bd7460fa1c0e35d92b7f118.',
    expect: {
      categories: ['credentials'],
      mustFlag: ['Autumn!Ledger42', '8f2c91ae4bd7460fa1c0e35d92b7f118'],
      minScore: 75,
    },
  },
  {
    id: 'R-12',
    name: 'JWT and private key header',
    kind: 'risky',
    text: 'Session token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QifQ.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx9fT3sample+not+a+real+key+material+placeholder\n-----END RSA PRIVATE KEY-----',
    expect: { categories: ['credentials'], mustFlag: ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', 'BEGIN RSA PRIVATE KEY'], minScore: 75 },
  },

  /* ---------------------------------------------------------------- */
  /* CATEGORY 4 — medical & sensitive personal data                    */
  /* ---------------------------------------------------------------- */
  {
    id: 'R-13',
    name: 'Clinical note with MRN, diagnosis and medication',
    kind: 'risky',
    text: 'Patient Marcus Chen (MRN 4482910) was diagnosed with type 2 diabetes and started on metformin 500mg. Insurance member ID BCB8837421. NPI 1488736202.',
    expect: {
      categories: ['medical_sensitive', 'contact'],
      mustFlag: ['4482910', 'type 2 diabetes', 'metformin', 'BCB8837421'],
      minScore: 75,
    },
  },
  {
    id: 'R-14',
    name: 'Mental health disclosure about a named colleague',
    kind: 'risky',
    text: 'Help me word this carefully: Samantha Kirby has been on sertraline for her depression and wants to discuss reduced hours.',
    expect: {
      categories: ['medical_sensitive', 'contact'],
      mustFlag: ['Samantha Kirby', 'sertraline', 'depression'],
      minScore: 45,
    },
  },
  {
    id: 'R-15',
    name: 'Immigration status disclosure',
    kind: 'risky',
    text: 'The candidate is currently on an H-1B and will need sponsorship required from October; their A-number is A123456789.',
    expect: { categories: ['medical_sensitive'], mustFlag: ['H-1B', 'A123456789'], minScore: 75 },
  },

  /* ---------------------------------------------------------------- */
  /* CATEGORY 5 — employee / client / volunteer records                */
  /* ---------------------------------------------------------------- */
  {
    id: 'R-16',
    name: 'HR performance and salary detail',
    kind: 'risky',
    text: 'Employee ID EMP-40218, Ravi Deshmukh, was placed on a performance improvement plan last month. His base salary is $86,500 and he reports to the regional lead.',
    expect: {
      categories: ['people_records'],
      mustFlag: ['EMP-40218', 'performance improvement plan', 'Ravi Deshmukh'],
      minScore: 45,
    },
  },
  {
    id: 'R-17',
    name: 'Volunteer record with safeguarding case reference',
    kind: 'risky',
    text: 'Volunteer ID VOL-2291 (Aisha Bello, aisha.bello@riverside-trust.invalid) is linked to safeguarding case number SG-88123. Please summarise the notes.',
    expect: {
      categories: ['people_records', 'contact'],
      mustFlag: ['VOL-2291', 'SG-88123', 'Aisha Bello', 'aisha.bello@riverside-trust.invalid'],
      minScore: 45,
    },
  },
  {
    id: 'R-18',
    name: 'Bulk people data',
    kind: 'risky',
    text: 'I am pasting our donor list below — can you clean up the formatting and remove duplicates from the client roster?',
    expect: { categories: ['people_records'], mustFlag: ['donor list'] },
  },

  /* ---------------------------------------------------------------- */
  /* CATEGORY 6 — confidential organisational information              */
  /* ---------------------------------------------------------------- */
  {
    id: 'R-19',
    name: 'Classified M&A memo',
    kind: 'risky',
    text: 'STRICTLY CONFIDENTIAL — Project Halberd is our acquisition of Northwind Trading Ltd; the contract value is $42M and the term sheet is signed. Do not distribute. Tracker: https://riverside.atlassian.net/browse/CORP-4417',
    expect: {
      categories: ['org_confidential'],
      mustFlag: ['STRICTLY CONFIDENTIAL', 'Halberd', 'term sheet', 'riverside.atlassian.net/browse/CORP-4417'],
      minScore: 45,
    },
  },
  {
    id: 'R-20',
    name: 'Unannounced restructuring',
    kind: 'risky',
    text: 'Internal use only: the reduction in force affects 40 roles in Q3 and the hiring freeze starts immediately. Draft the announcement.',
    expect: { categories: ['org_confidential'], mustFlag: ['Internal use only', 'reduction in force', 'hiring freeze'], minScore: 45 },
  },
  {
    id: 'R-21',
    name: 'Internal repository and ticket references',
    kind: 'risky',
    text: 'Clone git@github.invalid:riverside-internal/payments-core.git and look at the failure described in JIRA ticket PAY-2291.',
    expect: { categories: ['org_confidential'], mustFlag: ['git@github.invalid:riverside-internal/payments-core.git', 'PAY-2291'] },
  },

  /* ---------------------------------------------------------------- */
  /* EDGE CASES — precision under pressure                             */
  /* ---------------------------------------------------------------- */
  {
    id: 'E-01',
    name: 'Mixed prompt: one real secret inside otherwise safe text',
    kind: 'edge',
    text: 'The project meeting is scheduled for 3:00 PM. Before then, can you check why this call fails? curl -H "Authorization: Bearer sk-proj-9fQ2mZx7Lp0RtVb3Nw8KcJ4HdYs6Ae1Ug5Ti" https://api.example.com/v1/reports',
    expect: {
      categories: ['credentials'],
      mustFlag: ['sk-proj-9fQ2mZx7Lp0RtVb3Nw8KcJ4HdYs6Ae1Ug5Ti'],
      mustNotFlag: ['3:00 PM', 'project meeting'],
      minScore: 75,
    },
  },
  {
    id: 'E-02',
    name: 'Documentation-domain email should be low severity',
    kind: 'edge',
    text: 'In the docs example the support address is shown as help@example.com — should we change it?',
    expect: { categories: ['contact'], mustFlag: ['help@example.com'], maxSeverity: 'low' },
  },
  {
    id: 'E-03',
    name: 'Private IP and invoice number must not be treated as identity data',
    kind: 'edge',
    text: 'The service on 192.168.1.24 keeps timing out when it processes invoice number 88213394.',
    expect: { mustNotFlag: ['88213394'], maxScore: 24 },
  },
  {
    id: 'E-04',
    name: 'Repeated identical value should not inflate the score',
    kind: 'edge',
    text: 'Email casey.doyle@riverside-trust.invalid, then follow up with casey.doyle@riverside-trust.invalid, and cc casey.doyle@riverside-trust.invalid.',
    expect: { categories: ['contact'], mustFlag: ['casey.doyle@riverside-trust.invalid'], maxScore: 70 },
  },
  {
    id: 'E-05',
    name: 'Redacted output must stay readable and consistently labelled',
    kind: 'edge',
    text: 'Sarah Whitfield emailed Daniel Osei about the transfer; Sarah Whitfield will follow up tomorrow.',
    expect: {
      categories: ['contact'],
      mustFlag: ['Sarah Whitfield', 'Daniel Osei'],
      redactedContains: ['[NAME_1]', '[NAME_2]'],
      redactedNotContains: ['Sarah Whitfield', 'Daniel Osei'],
    },
  },
];

export default CASES;
