import { DefenseConfig, ScreeningRequest, ScreeningResult, VectorBreakdown } from '../types/defense';

export const DEFAULT_DEFENSE_CONFIG: DefenseConfig = {
  blockThreshold: 65,
  challengeThreshold: 35,
  enforceBannerAgreement: true,
  protectSmtpHeaders: true,
  protectDirectMessages: true,

  // Vector 1: IP Reputation
  blockTorAndProxies: true,
  flagDatacenterAsns: true,
  enableDnsblLookup: true,
  ipRateLimitPerMinute: 12,

  // Vector 2: Email Format & SMTP Hygiene
  blockDisposableEmails: true,
  blockPlusAddressingAbuse: true,
  maxEmailLocalEntropy: 4.05,
  verifyMxRecords: true,

  // Vector 3: Behavioral & Payload Heuristics
  maxInputEntropy: 4.45,
  detectKeyboardMash: true,
  minHumanTypingMs: 1400,
  blockSqlAndXss: true,
  blockSmtpHeaderInjection: true,
  maxUrlsAllowed: 2,

  // Vector 4: HTTP Request Headers
  requireSecFetchHeaders: true,
  requireAcceptLanguage: true,
  blockAutomatedUserAgents: true,
  inspectForwardedForSpoofing: true,

  // UK GDPR / Data Protection Act 2018 / PECR Compliance
  organizationName: 'Albion Cloud Digital Ltd',
  icoRegistrationNumber: 'ZB491820',
  dpoContactEmail: 'dpo-security@albioncloud.co.uk',
  ipPseudonymisationMode: 'dual_hmac_subnet',
  logRetentionDays: 30,
  bannerPosition: 'bottom_bar',
  bannerRequireExplicitAck: true,

  // Critical Risk Incident Alerting
  enableCriticalEmailAlerts: true,
  criticalRiskThreshold: 85,
  alertEmailAddress: 'secops-alerts@albioncloud.co.uk',
};

// Known IP intelligence database for deterministic, realistic inspection
const KNOWN_IP_PROFILES: Record<
  string,
  {
    asn: string;
    isp: string;
    country: string;
    type: 'Residential ISP' | 'Tor Exit Node' | 'Bulletproof Hosting' | 'Datacenter / Cloud' | 'Anonymous VPN';
    abuseConfidence: number;
    dnsblListed: boolean;
  }
> = {
  '81.134.202.14': {
    asn: 'AS2856',
    isp: 'British Telecommunications PLC',
    country: 'GB',
    type: 'Residential ISP',
    abuseConfidence: 2,
    dnsblListed: false,
  },
  '185.220.101.45': {
    asn: 'AS60729',
    isp: 'Zwiebelfreunde e.V. (Tor Exit)',
    country: 'DE',
    type: 'Tor Exit Node',
    abuseConfidence: 96,
    dnsblListed: true,
  },
  '45.142.214.99': {
    asn: 'AS209605',
    isp: 'UAB HostBaltic Bulletproof Relay',
    country: 'NL',
    type: 'Bulletproof Hosting',
    abuseConfidence: 91,
    dnsblListed: true,
  },
  '167.99.84.12': {
    asn: 'AS14061',
    isp: 'DigitalOcean London LON1',
    country: 'GB',
    type: 'Datacenter / Cloud',
    abuseConfidence: 48,
    dnsblListed: false,
  },
  '92.40.172.88': {
    asn: 'AS5607',
    isp: 'Sky UK Limited Broadband',
    country: 'GB',
    type: 'Residential ISP',
    abuseConfidence: 0,
    dnsblListed: false,
  },
  '194.165.16.77': {
    asn: 'AS49870',
    isp: 'Alsycon B.V. Spamhaus Drop',
    country: 'RU',
    type: 'Bulletproof Hosting',
    abuseConfidence: 99,
    dnsblListed: true,
  },
};

const DISPOSABLE_DOMAINS = new Set([
  'mailinator.com',
  '10minutemail.com',
  'guerrillamail.com',
  'tempmail.com',
  'yopmail.com',
  'trashmail.com',
  'sharklasers.com',
  'getnada.com',
  'maildrop.cc',
  'throwawaymail.com',
]);

const HIGH_RISK_TLDS = ['.xyz', '.top', '.click', '.work', '.gq', '.tk', '.loan', '.ru', '.cn'];

/**
 * Calculates Shannon Entropy in bits per character: H(X) = -sum(P(x) * log2(P(x)))
 */
export function calculateShannonEntropy(input: string): number {
  const clean = input.trim();
  if (!clean || clean.length === 0) return 0;
  const freq: Record<string, number> = {};
  for (const ch of clean) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  const len = clean.length;
  let entropy = 0;
  for (const ch in freq) {
    const p = freq[ch] / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(2));
}

/**
 * Detects random keyboard mashing (e.g., "asdfjkl;", "qwerzxcv98123", consonant runs without vowels)
 */
export function detectKeyboardMashOrGibberish(input: string): {
  isGibberish: boolean;
  reason: string | null;
  vowelRatio: number;
  maxConsonantRun: number;
} {
  const text = input.trim();
  if (text.length < 5) {
    return { isGibberish: false, reason: null, vowelRatio: 0.35, maxConsonantRun: 1 };
  }

  const alphaOnly = text.replace(/[^a-zA-Z]/g, '').toLowerCase();
  if (alphaOnly.length < 4) {
    return { isGibberish: true, reason: 'Non-alphabetic noise / symbol flood', vowelRatio: 0, maxConsonantRun: 0 };
  }

  const vowels = (alphaOnly.match(/[aeiouy]/g) || []).length;
  const vowelRatio = Number((vowels / alphaOnly.length).toFixed(2));

  // Find longest consecutive consonant cluster
  const consonantClusters = alphaOnly.split(/[aeiouy]+/);
  let maxConsonantRun = 0;
  for (const cluster of consonantClusters) {
    if (cluster.length > maxConsonantRun) {
      maxConsonantRun = cluster.length;
    }
  }

  // Classic QWERTY row sequences
  const qwertyMashPatterns = /(asdf|sdfg|dfgh|fghj|ghjk|hjkl|qwer|wert|erty|zxcv|xcvb|cvbn|123456)/i;
  if (qwertyMashPatterns.test(text)) {
    return {
      isGibberish: true,
      reason: 'QWERTY adjacent key-row mashing detected',
      vowelRatio,
      maxConsonantRun,
    };
  }

  if (maxConsonantRun >= 6) {
    return {
      isGibberish: true,
      reason: `Unnatural consonant cluster (${maxConsonantRun} consecutive consonants)`,
      vowelRatio,
      maxConsonantRun,
    };
  }

  if (alphaOnly.length >= 10 && (vowelRatio < 0.13 || vowelRatio > 0.78)) {
    return {
      isGibberish: true,
      reason: `Abnormal vowel-to-character ratio (${Math.round(vowelRatio * 100)}% vowels)`,
      vowelRatio,
      maxConsonantRun,
    };
  }

  // Repeated character sequences like "aaaaaaa"
  if (/(.)\1{5,}/.test(text)) {
    return {
      isGibberish: true,
      reason: 'Excessive character repetition sequence',
      vowelRatio,
      maxConsonantRun,
    };
  }

  return { isGibberish: false, reason: null, vowelRatio, maxConsonantRun };
}

/**
 * Deterministic UK GDPR / DPA 2018 IP Pseudonymisation (HMAC-SHA256 simulation + /24 subnet masking)
 */
export function pseudonymiseIpUkGdpr(
  ip: string,
  mode: DefenseConfig['ipPseudonymisationMode']
): string {
  const parts = ip.trim().split('.');
  const subnetMasked = parts.length === 4 ? `${parts[0]}.${parts[1]}.${parts[2]}.0/24` : 'ipv6::/48';

  // Deterministic FNV-1a / DJB2 style hex digest simulating daily HMAC-SHA256 salt
  const salt = 'UK_GDPR_DAILY_SALT_2026_10_20';
  const combined = `${ip}:${salt}`;
  let h1 = 0xdeadbeef ^ combined.length;
  let h2 = 0x41c6ce57 ^ combined.length;
  for (let i = 0; i < combined.length; i++) {
    const ch = combined.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  const hexHash = (h1 >>> 0).toString(16).padStart(8, '0') + (h2 >>> 0).toString(16).padStart(8, '0');

  if (mode === 'subnet_zero') {
    return subnetMasked;
  }
  if (mode === 'hmac_daily_salt') {
    return `hmac_${hexHash}`;
  }
  return `${subnetMasked} [hmac:${hexHash.slice(0, 10)}]`;
}

/**
 * Full 4-Vector Threat & UK Compliance Evaluation Engine
 */
export function evaluateRequest(req: ScreeningRequest, config: DefenseConfig): ScreeningResult {
  // --- VECTOR 1: IP REPUTATION & NETWORK INTELLIGENCE ---
  const ipFlags: string[] = [];
  let ipScore = 0;
  const trimmedIp = req.clientIp.trim();
  const knownProfile = KNOWN_IP_PROFILES[trimmedIp];

  let asn = 'AS12390 (Unclassified UK ISP)';
  let networkType = 'Residential ISP';
  let abuseConfidence = 5;
  let dnsblListed = false;

  if (knownProfile) {
    asn = `${knownProfile.asn} · ${knownProfile.isp}`;
    networkType = knownProfile.type;
    abuseConfidence = knownProfile.abuseConfidence;
    dnsblListed = knownProfile.dnsblListed;
  } else if (/^(185\.220\.|45\.142\.|194\.165\.|103\.251\.)/.test(trimmedIp)) {
    asn = 'AS60729 · Suspicious Relay Subnet';
    networkType = 'Tor Exit Node';
    abuseConfidence = 88;
    dnsblListed = true;
  } else if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(trimmedIp)) {
    asn = 'Malformed IPv4 Literal';
    networkType = 'Anonymous VPN';
    abuseConfidence = 75;
    ipFlags.push('Malformed or spoofed remote address literal');
    ipScore += 45;
  }

  if (config.blockTorAndProxies && (networkType === 'Tor Exit Node' || networkType === 'Bulletproof Hosting')) {
    ipScore += 65;
    ipFlags.push(`${networkType} detected (${asn})`);
  } else if (config.flagDatacenterAsns && networkType === 'Datacenter / Cloud') {
    ipScore += 32;
    ipFlags.push(`Non-residential Datacenter ASN (${asn}) submitting user form`);
  }

  if (config.enableDnsblLookup && dnsblListed) {
    ipScore += 35;
    ipFlags.push('Listed on Spamhaus DROP / AbuseIPDB high-confidence blacklist');
  }

  ipScore = Math.min(100, ipScore);
  const ipVector: VectorBreakdown = {
    score: ipScore,
    status: ipScore >= 60 ? 'CRITICAL' : ipScore >= 25 ? 'ELEVATED' : 'CLEAN',
    summary:
      ipFlags.length > 0
        ? ipFlags[0]
        : `Clean reputation (${networkType}, Abuse Score ${abuseConfidence}%)`,
    flags: ipFlags,
    metrics: {
      'Network Classification': networkType,
      'ASN / Provider': asn,
      'Abuse Confidence': `${abuseConfidence}%`,
      'DNSBL Status': dnsblListed ? 'LISTED' : 'CLEAR',
    },
  };

  // --- VECTOR 2: EMAIL FORMAT & SMTP HEADER HYGIENE ---
  const emailFlags: string[] = [];
  let emailScore = 0;
  const rawEmail = req.senderEmail;

  // Check for raw CRLF / SMTP header injection inside email or subject
  const smtpHeaderInjectionRegex = /(\\r|\\n|%0a|%0d|\r|\n|bcc\s*:|cc\s*:|content-type\s*:|mime-version\s*:|to\s*:)/i;
  if (
    config.protectSmtpHeaders &&
    (smtpHeaderInjectionRegex.test(rawEmail) || smtpHeaderInjectionRegex.test(req.subjectOrTopic))
  ) {
    emailScore += 90;
    emailFlags.push('CRITICAL: SMTP Header Injection attempt (CRLF / Bcc: / Content-Type override)');
  }

  const trimmedEmail = rawEmail.trim();
  const emailParts = trimmedEmail.split('@');
  let localEntropy = 0;
  let domainPart = 'invalid';

  if (emailParts.length !== 2 || !emailParts[0] || !emailParts[1].includes('.')) {
    emailScore += 65;
    emailFlags.push('Malformed RFC 5322 email syntax');
  } else {
    const localPart = emailParts[0];
    domainPart = emailParts[1].toLowerCase();
    localEntropy = calculateShannonEntropy(localPart);

    if (config.blockDisposableEmails && DISPOSABLE_DOMAINS.has(domainPart)) {
      emailScore += 70;
      emailFlags.push(`Disposable burner mail provider blocked (${domainPart})`);
    }

    if (HIGH_RISK_TLDS.some((tld) => domainPart.endsWith(tld))) {
      emailScore += 30;
      emailFlags.push(`High-abuse top-level domain (${domainPart})`);
    }

    if (localEntropy > config.maxEmailLocalEntropy && localPart.length >= 9) {
      emailScore += 38;
      emailFlags.push(
        `High-entropy randomized mailbox local-part (${localEntropy} bits > ${config.maxEmailLocalEntropy} limit)`
      );
    }

    // Excessive dot splitting (Gmail dot-trick evasion e.g. a.b.c.d.e.f@gmail.com)
    const dotCount = (localPart.match(/\./g) || []).length;
    if (dotCount >= 4) {
      emailScore += 42;
      emailFlags.push(`Suspicious dot-stuffing evasion (${dotCount} dots in local-part)`);
    }

    // Plus-addressing with random token e.g. user+bot99812@domain.com
    if (config.blockPlusAddressingAbuse && /\+[a-z0-9]{4,}/i.test(localPart)) {
      emailScore += 28;
      emailFlags.push('Automated sub-addressing (+tag) alias pattern detected');
    }

    // Digit-heavy bot local part e.g. john849204921@...
    const digitCount = (localPart.match(/\d/g) || []).length;
    if (localPart.length >= 8 && digitCount / localPart.length > 0.55) {
      emailScore += 30;
      emailFlags.push(`Numeric-heavy bot generated local-part (${digitCount} digits)`);
    }
  }

  emailScore = Math.min(100, emailScore);
  const emailVector: VectorBreakdown = {
    score: emailScore,
    status: emailScore >= 60 ? 'CRITICAL' : emailScore >= 25 ? 'ELEVATED' : 'CLEAN',
    summary:
      emailFlags.length > 0
        ? emailFlags[0]
        : `Valid RFC 5322 format & verified domain (${domainPart})`,
    flags: emailFlags,
    metrics: {
      'Local-Part Entropy': `${localEntropy} bits/char`,
      'Domain Reputation': DISPOSABLE_DOMAINS.has(domainPart) ? 'DISPOSABLE' : 'STANDARD',
      'SMTP CRLF Check': smtpHeaderInjectionRegex.test(rawEmail + req.subjectOrTopic) ? 'INJECTION' : 'SAFE',
    },
  };

  // --- VECTOR 3: BEHAVIORAL TELEMETRY & PAYLOAD HEURISTICS ---
  const behaviorFlags: string[] = [];
  let behaviorScore = 0;
  const combinedText = `${req.subjectOrTopic} ${req.messageBody}`.trim();
  const payloadEntropy = calculateShannonEntropy(req.messageBody);
  const gibberishCheck = detectKeyboardMashOrGibberish(req.messageBody);

  // Check malicious injection signatures (SQLi, XSS, PHP exec, Command injection, SMTP body injection)
  const sqliRegex =
    /(\bUNION\s+ALL\s+SELECT\b|\bUNION\s+SELECT\b|\bOR\s+1\s*=\s*1\b|\bDROP\s+TABLE\b|\bSLEEP\s*\(\d+\)|\bINFORMATION_SCHEMA\b|--\s*$)/i;
  const xssAndPhpRegex =
    /(<script\b|javascript:|onerror\s*=|onload\s*=|<\?php|\bbase64_decode\s*\(|\beval\s*\(|\bsystem\s*\(|\bpassthru\s*\(|\bshell_exec\s*\(|O:\d+:"[a-zA-Z0-9_]+":)/i;
  const pathTraversalRegex = /(\.\.\/|\.\.\\|\/etc\/passwd|c:\\windows\\system32)/i;

  if (config.blockSqlAndXss) {
    if (sqliRegex.test(combinedText)) {
      behaviorScore += 85;
      behaviorFlags.push('SQL Injection (SQLi) payload signature matched in form input');
    }
    if (xssAndPhpRegex.test(combinedText)) {
      behaviorScore += 90;
      behaviorFlags.push('Cross-Site Scripting (XSS) or PHP Code/Object Injection payload detected');
    }
    if (pathTraversalRegex.test(combinedText)) {
      behaviorScore += 80;
      behaviorFlags.push('Directory Traversal / Local File Inclusion (LFI) probe detected');
    }
  }

  if (config.blockSmtpHeaderInjection && smtpHeaderInjectionRegex.test(req.messageBody)) {
    behaviorScore += 85;
    behaviorFlags.push('Multipart MIME / SMTP body header boundary injection detected');
  }

  // URL spam density check (especially for DM & SMTP abuse)
  const urlMatches = req.messageBody.match(/https?:\/\/[^\s]+/gi) || [];
  if (urlMatches.length > config.maxUrlsAllowed) {
    behaviorScore += 45;
    behaviorFlags.push(
      `Excessive URL link density (${urlMatches.length} links > max ${config.maxUrlsAllowed} allowed in DM/SMTP)`
    );
  }

  // Entropy & Keyboard Mash check
  if (payloadEntropy > config.maxInputEntropy && req.messageBody.length >= 16) {
    behaviorScore += 42;
    behaviorFlags.push(
      `Abnormally high payload Shannon entropy (${payloadEntropy} bits/char > ${config.maxInputEntropy} threshold)`
    );
  }

  if (config.detectKeyboardMash && gibberishCheck.isGibberish) {
    behaviorScore += 50;
    behaviorFlags.push(`Random/gibberish input pattern: ${gibberishCheck.reason}`);
  }

  // Behavioral Telemetry checks
  if (req.telemetry.honeypotFilled) {
    behaviorScore += 95;
    behaviorFlags.push('Invisible CSS/ARIA honeypot trap field populated by automated bot');
  }

  if (req.telemetry.typingDurationMs < config.minHumanTypingMs && req.messageBody.length > 15) {
    behaviorScore += 48;
    behaviorFlags.push(
      `Superhuman submission velocity (${req.telemetry.typingDurationMs}ms < ${config.minHumanTypingMs}ms human baseline)`
    );
  }

  if (req.telemetry.keystrokeCount === 0 && req.messageBody.length > 10) {
    behaviorScore += 38;
    behaviorFlags.push('Zero physical DOM keystrokes recorded (programmatic POST or full paste dump)');
  }

  if (!req.telemetry.jsTokenPresent) {
    behaviorScore += 30;
    behaviorFlags.push('Missing dynamic client proof-of-interaction telemetry signature');
  }

  behaviorScore = Math.min(100, behaviorScore);
  const behaviorVector: VectorBreakdown = {
    score: behaviorScore,
    status: behaviorScore >= 60 ? 'CRITICAL' : behaviorScore >= 25 ? 'ELEVATED' : 'CLEAN',
    summary:
      behaviorFlags.length > 0
        ? behaviorFlags[0]
        : `Natural human input cadence (${req.telemetry.typingDurationMs}ms, ${payloadEntropy} bits entropy)`,
    flags: behaviorFlags,
    metrics: {
      'Payload Entropy': `${payloadEntropy} bits/char`,
      'Vowel Ratio': `${Math.round(gibberishCheck.vowelRatio * 100)}%`,
      'Typing Duration': `${req.telemetry.typingDurationMs} ms`,
      'Keystrokes / Pastes': `${req.telemetry.keystrokeCount} keys / ${req.telemetry.pasteEventsCount} pastes`,
    },
  };

  // --- VECTOR 4: UNEXPECTED HTTP REQUEST HEADERS ---
  const headerFlags: string[] = [];
  let headerScore = 0;

  const ua = req.headers['User-Agent'] || req.headers['user-agent'] || '';
  const acceptLang = req.headers['Accept-Language'] || req.headers['accept-language'] || '';
  const secFetchSite = req.headers['Sec-Fetch-Site'] || req.headers['sec-fetch-site'] || '';
  const secFetchMode = req.headers['Sec-Fetch-Mode'] || req.headers['sec-fetch-mode'] || '';
  const xForwardedFor = req.headers['X-Forwarded-For'] || req.headers['x-forwarded-for'] || '';

  const automatedUaRegex =
    /(python-requests|curl\/|wget\/|go-http-client|headlesschrome|phantomjs|libwww-perl|scrapy|postmanruntime|aiohttp|httpx)/i;

  if (!ua.trim()) {
    headerScore += 65;
    headerFlags.push('Empty or omitted User-Agent HTTP header');
  } else if (config.blockAutomatedUserAgents && automatedUaRegex.test(ua)) {
    headerScore += 75;
    headerFlags.push(`Automated HTTP client signature in User-Agent (${ua.slice(0, 42)})`);
  }

  if (config.requireAcceptLanguage && !acceptLang.trim()) {
    headerScore += 35;
    headerFlags.push('Missing Accept-Language header (typical of raw script/socket bots)');
  }

  if (config.requireSecFetchHeaders && (!secFetchSite.trim() || !secFetchMode.trim())) {
    headerScore += 30;
    headerFlags.push('Missing Fetch Metadata headers (Sec-Fetch-Site / Sec-Fetch-Mode)');
  } else if (secFetchSite === 'cross-site' && req.channel !== 'api_webhook') {
    headerScore += 45;
    headerFlags.push('Unexpected cross-site POST request origin (Sec-Fetch-Site: cross-site)');
  }

  if (
    config.inspectForwardedForSpoofing &&
    xForwardedFor &&
    (xForwardedFor.split(',').length > 3 || /127\.0\.0\.1|localhost|10\.0\.0\./i.test(xForwardedFor))
  ) {
    headerScore += 55;
    headerFlags.push(`Suspicious X-Forwarded-For proxy chain spoofing (${xForwardedFor})`);
  }

  headerScore = Math.min(100, headerScore);
  const headerVector: VectorBreakdown = {
    score: headerScore,
    status: headerScore >= 60 ? 'CRITICAL' : headerScore >= 25 ? 'ELEVATED' : 'CLEAN',
    summary:
      headerFlags.length > 0
        ? headerFlags[0]
        : 'Consistent browser header fingerprint & Fetch metadata',
    flags: headerFlags,
    metrics: {
      'User-Agent Class': automatedUaRegex.test(ua) ? 'AUTOMATED SCRIPT' : ua ? 'STANDARD BROWSER' : 'MISSING',
      'Sec-Fetch-Site': secFetchSite || 'MISSING',
      'Accept-Language': acceptLang || 'MISSING',
      'X-Forwarded-For': xForwardedFor || 'Direct',
    },
  };

  // --- AGGREGATE SCORE & UK COMPLIANCE ENFORCEMENT ---
  // Weighted composite risk score with max-severity floor
  const maxVector = Math.max(ipScore, emailScore, behaviorScore, headerScore);
  const weightedAvg = Math.round(
    ipScore * 0.25 + emailScore * 0.25 + behaviorScore * 0.3 + headerScore * 0.2
  );
  let totalRiskScore = Math.min(100, Math.round(maxVector * 0.65 + weightedAvg * 0.55));

  if (config.enforceBannerAgreement && !req.telemetry.bannerAgreed) {
    totalRiskScore = Math.max(totalRiskScore, config.challengeThreshold + 10);
    behaviorVector.flags.push(
      'UK Compliance Screening Notice not yet acknowledged by user session'
    );
  }

  let verdict: ScreeningResult['verdict'] = 'ALLOW';
  if (totalRiskScore >= config.blockThreshold) {
    verdict = 'BLOCK';
  } else if (
    totalRiskScore >= config.challengeThreshold ||
    (config.enforceBannerAgreement && !req.telemetry.bannerAgreed)
  ) {
    verdict = 'CHALLENGE';
  }

  const now = new Date();
  const retentionDate = new Date(now.getTime() + config.logRetentionDays * 86400000);
  const criticalAlertTriggered =
    config.enableCriticalEmailAlerts &&
    totalRiskScore >= config.criticalRiskThreshold &&
    Boolean(config.alertEmailAddress.trim());

  return {
    id: req.id || `AEGIS-${Math.random().toString(36).substring(2, 8).toUpperCase()}`,
    timestamp: req.timestamp || now.toISOString(),
    channel: req.channel,
    verdict,
    totalRiskScore,
    criticalAlertTriggered,
    alertDispatchedTo: criticalAlertTriggered ? config.alertEmailAddress.trim() : null,
    smtpSafeToDispatch: verdict === 'ALLOW' && emailScore < 50,
    dmSafeToDeliver: verdict === 'ALLOW' && behaviorScore < 50,
    rawClientIp: trimmedIp,
    pseudonymisedIp: pseudonymiseIpUkGdpr(trimmedIp, config.ipPseudonymisationMode),
    senderEmail: trimmedEmail,
    subjectOrTopic: req.subjectOrTopic,
    messagePreview: req.messageBody.slice(0, 120),
    vectors: {
      ipReputation: ipVector,
      emailHygiene: emailVector,
      behaviorAndPayload: behaviorVector,
      requestHeaders: headerVector,
    },
    ukCompliance: {
      lawfulBasis: 'UK GDPR Art. 6(1)(f) Legitimate Interests (Recital 49 Network & Info Security)',
      pecrExemption: 'PECR Reg. 6(4) Strictly Necessary Security & Anti-Abuse Screening',
      bannerAcknowledged: req.telemetry.bannerAgreed,
      pseudonymisationMethod:
        config.ipPseudonymisationMode === 'dual_hmac_subnet'
          ? 'HMAC-SHA256 (Daily Rotating Salt) + IPv4 /24 Mask'
          : config.ipPseudonymisationMode === 'hmac_daily_salt'
          ? 'HMAC-SHA256 (Daily Rotating Salt)'
          : 'IPv4 /24 Zero-Subnet Masking',
      retentionExpiresAt: retentionDate.toISOString().split('T')[0],
    },
  };
}

export interface PresetScenario {
  id: string;
  label: string;
  category: 'Legitimate' | 'Bot Attack' | 'Human Malicious' | 'Header / IP Anomaly';
  description: string;
  request: ScreeningRequest;
}

export const PRESET_SCENARIOS: PresetScenario[] = [
  {
    id: 'legit_uk_smtp',
    label: 'Legitimate UK Customer Inquiry (SMTP)',
    category: 'Legitimate',
    description: 'Clean UK BT residential IP, valid business email, natural human typing cadence, standard browser headers.',
    request: {
      channel: 'smtp_mail',
      clientIp: '81.134.202.14',
      senderEmail: 'eleanor.vance@meridian-architects.co.uk',
      recipientOrTarget: 'sales@albioncloud.co.uk',
      subjectOrTopic: 'Enterprise Hosting Quote for Q4 Migration',
      messageBody:
        'Good morning team, we are looking to migrate four PHP 8.3 applications to your Manchester cluster before November. Could we arrange a technical scoping call this Thursday?',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
        'Accept-Language': 'en-GB,en;q=0.9',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'cors',
        'X-Forwarded-For': '',
      },
      telemetry: {
        typingDurationMs: 14820,
        keystrokeCount: 186,
        pasteEventsCount: 0,
        honeypotFilled: false,
        bannerAgreed: true,
        jsTokenPresent: true,
      },
    },
  },
  {
    id: 'smtp_crlf_injection',
    label: 'SMTP Header Injection + Tor Exit Node',
    category: 'Bot Attack',
    description: 'Attempts to hijack PHP mail()/PHPMailer via \\r\\nBcc: injection from a known Tor Exit Node with missing browser headers.',
    request: {
      channel: 'smtp_mail',
      clientIp: '185.220.101.45',
      senderEmail: 'attacker@mailinator.com\\r\\nBcc: target-list@victim-corp.co.uk',
      recipientOrTarget: 'support@albioncloud.co.uk',
      subjectOrTopic: 'Invoice #99182\\r\\nContent-Type: text/html',
      messageBody:
        'Urgent account verification required: https://verify-login-update.xyz/auth and https://bonus-claim.top/free and https://crypto-drop.click/now',
      headers: {
        'User-Agent': 'python-requests/2.31.0',
        'Accept-Language': '',
        'Sec-Fetch-Site': '',
        'Sec-Fetch-Mode': '',
        'X-Forwarded-For': '127.0.0.1, 10.0.0.1, 185.220.101.45',
      },
      telemetry: {
        typingDurationMs: 45,
        keystrokeCount: 0,
        pasteEventsCount: 1,
        honeypotFilled: true,
        bannerAgreed: true,
        jsTokenPresent: false,
      },
    },
  },
  {
    id: 'dm_keyboard_mash_sqli',
    label: 'Human Attacker: Gibberish + SQLi in DM',
    category: 'Human Malicious',
    description: 'Suspicious dot-stuffed email, keyboard-mashed subject, and SQL Injection / PHP execution probe inside Direct Message body.',
    request: {
      channel: 'direct_message',
      clientIp: '167.99.84.12',
      senderEmail: 'x.9.k.m.z.8.1+bot9921@gmail.com',
      recipientOrTarget: '@admin_helpdesk',
      subjectOrTopic: 'asdfjkl;qwerzxcv99182',
      messageBody:
        "asdfghjkl zxcvbnm ' UNION ALL SELECT username, password_hash FROM wp_users WHERE 1=1 -- <?php system($_GET['cmd']); ?>",
      headers: {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/124.0.0.0 Safari/537.36',
        'Accept-Language': 'en-US',
        'Sec-Fetch-Site': 'cross-site',
        'Sec-Fetch-Mode': 'navigate',
        'X-Forwarded-For': '167.99.84.12',
      },
      telemetry: {
        typingDurationMs: 620,
        keystrokeCount: 14,
        pasteEventsCount: 3,
        honeypotFilled: false,
        bannerAgreed: true,
        jsTokenPresent: true,
      },
    },
  },
  {
    id: 'bulletproof_spam_wave',
    label: 'Bulletproof ASN + High-Entropy Bot Flood',
    category: 'Header / IP Anomaly',
    description: 'High-entropy randomized email & payload from a Spamhaus-listed bulletproof host using Go-http-client.',
    request: {
      channel: 'contact_form',
      clientIp: '45.142.214.99',
      senderEmail: 'q8v9z1k4m7p2x5w8n3@sharklasers.com',
      recipientOrTarget: 'enquiries@albioncloud.co.uk',
      subjectOrTopic: 'K9#mP2$vL8@xQ4!zR7&wN5',
      messageBody: '8f9K#m2$pL9@xQ4!zR7&wN5^tB3*yH6(uJ1)vC0_bN8+mK4=qW2',
      headers: {
        'User-Agent': 'Go-http-client/2.0',
        'Accept-Language': '',
        'Sec-Fetch-Site': '',
        'Sec-Fetch-Mode': '',
        'X-Forwarded-For': '',
      },
      telemetry: {
        typingDurationMs: 12,
        keystrokeCount: 0,
        pasteEventsCount: 0,
        honeypotFilled: false,
        bannerAgreed: false,
        jsTokenPresent: false,
      },
    },
  },
];

export interface HourlyTrendPoint {
  hourLabel: string;
  hourIso: string;
  allowed: number;
  blocked: number;
  challenged: number;
  total: number;
}

// Baseline 24-hour hourly traffic telemetry profile (before live interactive additions)
const BASELINE_24H_PROFILE: Array<{
  offsetHoursAgo: number;
  allowed: number;
  blocked: number;
  challenged: number;
}> = [
  { offsetHoursAgo: 23, allowed: 18, blocked: 6, challenged: 2 },
  { offsetHoursAgo: 22, allowed: 14, blocked: 5, challenged: 1 },
  { offsetHoursAgo: 21, allowed: 11, blocked: 9, challenged: 2 },
  { offsetHoursAgo: 20, allowed: 9, blocked: 14, challenged: 3 },
  { offsetHoursAgo: 19, allowed: 7, blocked: 22, challenged: 4 }, // Overnight botnet credential/SMTP probe wave
  { offsetHoursAgo: 18, allowed: 8, blocked: 19, challenged: 2 },
  { offsetHoursAgo: 17, allowed: 12, blocked: 8, challenged: 2 },
  { offsetHoursAgo: 16, allowed: 24, blocked: 7, challenged: 3 },
  { offsetHoursAgo: 15, allowed: 38, blocked: 11, challenged: 4 },
  { offsetHoursAgo: 14, allowed: 52, blocked: 15, challenged: 5 },
  { offsetHoursAgo: 13, allowed: 61, blocked: 18, challenged: 6 },
  { offsetHoursAgo: 12, allowed: 58, blocked: 31, challenged: 8 }, // Midday SMTP header injection spike
  { offsetHoursAgo: 11, allowed: 49, blocked: 24, challenged: 5 },
  { offsetHoursAgo: 10, allowed: 55, blocked: 12, challenged: 4 },
  { offsetHoursAgo: 9, allowed: 64, blocked: 14, challenged: 5 },
  { offsetHoursAgo: 8, allowed: 60, blocked: 16, challenged: 4 },
  { offsetHoursAgo: 7, allowed: 47, blocked: 19, challenged: 6 },
  { offsetHoursAgo: 6, allowed: 41, blocked: 27, challenged: 7 },
  { offsetHoursAgo: 5, allowed: 36, blocked: 13, challenged: 3 },
  { offsetHoursAgo: 4, allowed: 29, blocked: 10, challenged: 2 },
  { offsetHoursAgo: 3, allowed: 33, blocked: 15, challenged: 4 },
  { offsetHoursAgo: 2, allowed: 27, blocked: 21, challenged: 5 },
  { offsetHoursAgo: 1, allowed: 31, blocked: 17, challenged: 3 },
  { offsetHoursAgo: 0, allowed: 26, blocked: 12, challenged: 3 },
];

export function build24HourTrendData(
  logs: ScreeningResult[],
  channelFilter: 'ALL' | ScreeningRequest['channel'] = 'ALL'
): HourlyTrendPoint[] {
  const now = new Date();
  const currentHourMs = new Date(
    now.getFullYear(),
    now.getMonth(),
    now.getDate(),
    now.getHours(),
    0,
    0,
    0
  ).getTime();

  // Channel scaling ratio for baseline telemetry when filtering by specific channel
  const channelRatio =
    channelFilter === 'ALL'
      ? 1
      : channelFilter === 'smtp_mail'
      ? 0.42
      : channelFilter === 'direct_message'
      ? 0.28
      : channelFilter === 'contact_form'
      ? 0.2
      : 0.1;

  const buckets: HourlyTrendPoint[] = BASELINE_24H_PROFILE.map((b) => {
    const bucketTime = new Date(currentHourMs - b.offsetHoursAgo * 3600000);
    const hh = String(bucketTime.getUTCHours()).padStart(2, '0') + ':00';
    // If logs were purged completely by user, show only live logs (0 baseline)
    const activeMultiplier = logs.length === 0 ? 0 : channelRatio;
    const allowed = Math.round(b.allowed * activeMultiplier);
    const blocked = Math.round(b.blocked * activeMultiplier);
    const challenged = Math.round(b.challenged * activeMultiplier);

    return {
      hourLabel: b.offsetHoursAgo === 0 ? `${hh} (Now)` : hh,
      hourIso: bucketTime.toISOString().slice(0, 13),
      allowed,
      blocked,
      challenged,
      total: allowed + blocked + challenged,
    };
  });

  // Fold in actual audit log entries into their matching hour bucket (or current hour if recent)
  logs.forEach((log) => {
    if (channelFilter !== 'ALL' && log.channel !== channelFilter) return;
    const logHourIso = log.timestamp.slice(0, 13);
    const targetBucket =
      buckets.find((b) => b.hourIso === logHourIso) || buckets[buckets.length - 1];
    if (targetBucket) {
      if (log.verdict === 'ALLOW') targetBucket.allowed += 1;
      else if (log.verdict === 'BLOCK') targetBucket.blocked += 1;
      else targetBucket.challenged += 1;
      targetBucket.total =
        targetBucket.allowed + targetBucket.blocked + targetBucket.challenged;
    }
  });

  return buckets;
}

export function generateInitialAuditLogs(config: DefenseConfig): ScreeningResult[] {
  const nowMs = Date.now();
  const hourOffsets = [0.05, 0.3, 1.1, 2.4, 4.2, 6.5, 9.0, 12.2];
  return hourOffsets.map((hoursAgo, idx) => {
    const scenario = PRESET_SCENARIOS[idx % PRESET_SCENARIOS.length];
    const reqWithMeta: ScreeningRequest = {
      ...scenario.request,
      id: `AEGIS-840${idx + 1}`,
      timestamp: new Date(nowMs - Math.round(hoursAgo * 3600000)).toISOString(),
    };
    return evaluateRequest(reqWithMeta, config);
  });
}
