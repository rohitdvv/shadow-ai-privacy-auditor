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
export const GIVEN_NAMES = set([
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
export const HONORIFICS = set([
  'mr','mrs','ms','miss','mx','dr','prof','professor','rev','reverend','fr','sir','dame',
  'lord','lady','capt','captain','sgt','lt','col','gen','hon','judge','nurse','pastor','rabbi','imam',
]);

/**
 * Words that are frequently capitalised but are not people.
 * This list is the single biggest defence against over-redaction.
 */
export const NAME_STOPWORDS = set([
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
export const PERSON_CONTEXT_CUES = [
  'patient','client','employee','volunteer','donor','beneficiary','candidate','applicant','tenant',
  'student','member','customer','contact','colleague','coworker','manager','supervisor','director',
  'nurse','doctor','physician','therapist','caseworker','social worker','attorney','lawyer',
  'name is','named','called','signed by','attn','attention','cc','bcc','regards','sincerely',
  'reports to','managed by','assigned to','spoke with','met with','emailed','called by','on behalf of',
  'mr','mrs','ms','dr','prof','my','our','his','her','their',
];

/** Organisation suffixes — used to label ORG rather than PERSON. */
export const ORG_SUFFIXES = set([
  'inc','inc.','llc','l.l.c.','ltd','ltd.','limited','plc','gmbh','ag','sa','sas','bv','nv','oy','ab',
  'corp','corp.','corporation','company','co','co.','group','holdings','partners','associates','ventures',
  'foundation','trust','society','association','institute','university','college','school','hospital',
  'clinic','council','charity','ngo','nonprofit','coop','cooperative','union','federation','alliance',
]);

/** Health conditions / clinical concepts. Presence of these makes surrounding text special-category. */
export const MEDICAL_CONDITIONS = [
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
export const MEDICATIONS = [
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
export const MEDICAL_CONTEXT = [
  'patient','diagnosis','diagnosed','prognosis','symptom','symptoms','treatment','treated','therapy',
  'prescription','prescribed','dosage','dose','mg','ml','medication','medications','clinical','clinician',
  'physician','doctor','nurse','hospital','clinic','ward','icu','er','emergency room','admitted','discharge',
  'discharged','referral','referred','lab result','blood test','biopsy','mri','ct scan','x-ray','ultrasound',
  'medical record','health record','chart','ehr','emr','insurance claim','copay','deductible','icd',
  'allergy','allergies','vitals','bp','a1c','cholesterol','history of','presents with','follow-up appointment',
];

/** Immigration / legal-status vocabulary (special-category, frequently pasted into AI tools). */
export const IMMIGRATION_TERMS = [
  'green card','permanent resident','lawful permanent resident','naturalization','naturalisation',
  'asylum seeker','asylum application','refugee status','undocumented','out of status','overstayed',
  'work permit','work authorization','work authorisation','ead card','visa status','visa expired',
  'h-1b','h1b','h-4','l-1','l1 visa','o-1','tn visa','f-1','f1 visa','opt','cpt','j-1','b-1','b-2',
  'uscis','immigration case','deportation','removal proceedings','ice detention','daca','tps',
  'sponsorship required','requires sponsorship','alien registration','a-number',
];

/** Protected / special-category attributes about a person. */
export const PROTECTED_ATTRIBUTES = [
  'sexual orientation','gay','lesbian','bisexual','transgender','non-binary','nonbinary','queer',
  'gender identity','gender reassignment','trade union member','union membership','union organiser',
  'political affiliation','voted for','party membership','religious belief','practising muslim',
  'practicing muslim','practising christian','practicing christian','observant jew','devout hindu',
  'converted to','ethnic origin','ethnicity','race','racial background','caste','indigenous status',
  'criminal record','prior conviction','arrest record','on probation','parole','sex offender registry',
  'biometric data','fingerprint template','facial recognition template','dna profile','genetic test',
];

/** Confidentiality classification markers. */
export const CONFIDENTIALITY_MARKERS = [
  'strictly confidential','company confidential','confidential and proprietary',
  'privileged and confidential','attorney-client privileged','internal use only','internal only',
  'do not distribute','do not forward','not for distribution','not for external release',
  'restricted distribution','classified','trade secret','proprietary information','under nda',
  'subject to nda','embargoed','pre-release','need to know','commercial in confidence',
];

/** Business-sensitive concepts (unannounced financials, deals, restructuring). */
export const BUSINESS_SENSITIVE = [
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
export const PLACEHOLDER_CUES = [
  'example','e.g.','for example','sample','dummy','placeholder','fictional','fake','made up','made-up',
  'test data','testing only','lorem ipsum','foo','bar','baz','xxx','yyy','zzz','redacted','anonymised',
  'anonymized','john doe','jane doe','acme','contoso','example.com','example.org','test@','not real',
  'hypothetical','illustrative','template','mock','demo only',
];

/** Common English words that must never be treated as a secret value. */
export const COMMON_WORDS = set([
  'password','secret','required','important','correct','incorrect','changed','updated','expired','invalid',
  'missing','unknown','provided','available','disabled','enabled','something','anything','nothing',
  'strong','weak','simple','complex','default','standard','custom','private','public','hidden','visible',
  'confidential','sensitive','encrypted','hashed','stored','shared','rotated','reset','blank','empty',
  'letters','numbers','characters','symbols','uppercase','lowercase','minimum','maximum','optional',
]);
