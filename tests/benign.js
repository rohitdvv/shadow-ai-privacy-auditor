/**
 * Benign prompt corpus — the false-positive harness.
 *
 * These are ordinary things people ask an AI assistant. None of them contains
 * sensitive information, so the auditor must return zero findings for every
 * one. This is the measurement behind the "does not over-redact" claim: the
 * category assertions in cases.js prove recall, this file proves precision.
 *
 * All content is invented for this project.
 */

export const BENIGN_PROMPTS = [
  'The project meeting is scheduled for 3:00 PM.',
  'Rewrite this paragraph in plain English for a general audience.',
  'What are three ways to make a status update easier to skim?',
  'Explain the difference between a merge and a rebase in git.',
  'Give me a 200-word summary of how solar panels convert light into electricity.',
  'Draft an agenda for a 45 minute retrospective with eight people.',
  'What questions should I ask when reviewing a vendor renewal?',
  'Suggest five names for an internal book club.',
  'How do I write a regular expression that matches a UK postcode?',
  'Convert this bulleted list into a short paragraph.',
  'Write unit tests for a function that validates an email address format.',
  'What is the recommended way to handle pagination in a REST API?',
  'Summarise the pros and cons of a four day working week.',
  'Turn these rough notes into three action items with owners left blank.',
  'What does OKR stand for and how is it different from a KPI?',
  'Explain recursion to someone who has never programmed before.',
  'Draft a polite decline to a meeting invitation I cannot attend.',
  'How should I structure a one page project brief?',
  'What is the typical notice period in a standard employment contract?',
  'Create a checklist for onboarding a new team member.',
  'Rewrite this sentence in the active voice.',
  'What are common accessibility issues in web forms?',
  'Explain what a load balancer does using an analogy.',
  'Give me an outline for a 10 slide presentation about volunteer recruitment.',
  'How do I calculate a weighted average in a spreadsheet?',
  'What is the difference between qualitative and quantitative research?',
  'Suggest three icebreaker questions for a remote workshop.',
  'Write a short thank-you message for a team that shipped on time.',
  'What is the best way to version a public API?',
  'Explain the Pareto principle with a workplace example.',
  'The office will be closed on Monday for scheduled maintenance.',
  'Increase the timeout from 30 seconds to 60 seconds and retry twice.',
  'Our Q3 planning workshop runs from 9:00 AM to 4:30 PM on 12 September.',
  'Compare Python and JavaScript for data processing scripts.',
  'What should a good README contain?',
  'Draft three subject lines for a newsletter about community gardening.',
  'How many words should an executive summary be?',
  'Explain how HTTPS protects data in transit.',
  'What are the main stages of a typical grant application process?',
  'Give feedback on this sentence: "We are excited to announce our new website."',
  'Write a SQL query that counts rows grouped by month.',
  'What is a reasonable target for a customer satisfaction score?',
  'Suggest a filing structure for a shared documents folder.',
  'Explain the difference between gross and net revenue.',
  'How do I politely follow up on an unanswered email?',
];

export default BENIGN_PROMPTS;
