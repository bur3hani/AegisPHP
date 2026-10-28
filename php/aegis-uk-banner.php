<?php
/**
 * aegis-uk-banner.php — UK GDPR (Art. 6(1)(f) & Art. 13) + PECR Reg. 6 Transparency Banner
 * Project: BuruOps AegisPHP (https://github.com/buruops/aegis-php)
 * Author: BuruOps (engr.buru@gmail.com)
 * License: MIT License with Attribution (BuruOps)
 *
 * Include this snippet inside your PHP layout or form template:
 * <?php include_once __DIR__ . '/aegis-uk-banner.php'; ?>
 */

$orgName   = htmlspecialchars($organizationName ?? 'BuruOps Protected Service', ENT_QUOTES, 'UTF-8');
$icoNumber = htmlspecialchars($icoRegNumber ?? 'ZB491820', ENT_QUOTES, 'UTF-8');
$retention = (int) ($logRetentionDays ?? 30);
?>
<!-- AegisPHP UK Regulatory Security Screening Notice (Powered by BuruOps) -->
<div id="aegis-uk-security-banner"
     role="region"
     aria-label="UK Data Protection & Automated Security Screening Notice"
     style="position:fixed;bottom:0;left:0;right:0;z-index:9999;background:#0b1120;color:#f1f5f9;border-top:1px solid #1e293b;padding:12px 20px;font-family:system-ui,-apple-system,sans-serif;font-size:13px;display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;">
  <div style="flex:1;min-width:280px;line-height:1.5;">
    <strong style="color:#38bdf8;">UK Security &amp; Anti-Abuse Screening Active:</strong>
    By accessing this website, submitting forms, or dispatching SMTP / Direct Messages, you acknowledge and agree that your request headers, IP reputation (pseudonymised), email format, and input behaviour are screened in real time by
    <strong><?= $orgName ?></strong> (ICO Reg: <code><?= $icoNumber ?></code>) under
    <em>UK GDPR Art. 6(1)(f) (Recital 49 Network Security)</em> and <em>PECR Reg. 6</em>.
    Logs are pseudonymised and retained for a maximum of <strong><?= $retention ?> days</strong>.
  </div>
  <div style="display:flex;align-items:center;gap:10px;flex-shrink:0;">
    <button type="button"
            id="aegis-ack-btn"
            style="background:#0284c7;color:#ffffff;border:none;padding:8px 16px;border-radius:6px;font-weight:600;cursor:pointer;font-size:12px;transition:background 0.2s;">
      Agree &amp; Acknowledge Screening
    </button>
  </div>
</div>

<script>
(function() {
  const startTs = performance.now();
  let keystrokes = 0;
  let pastes = 0;

  document.addEventListener('keydown', () => { keystrokes++; }, { passive: true });
  document.addEventListener('paste', () => { pastes++; }, { passive: true });

  // Inject hidden telemetry & honeypot fields into all protected forms
  function bindProtectedForms() {
    document.querySelectorAll('form[data-aegis-protect], form').forEach((form) => {
      if (form.dataset.aegisBound) return;
      form.dataset.aegisBound = '1';

      form.insertAdjacentHTML('beforeend', `
        <div style="position:absolute;left:-9999px;top:-9999px;opacity:0;pointer-events:none;" aria-hidden="true">
          <label>Leave this field blank <input type="text" name="_aegis_hp_website" tabindex="-1" autocomplete="off"></label>
        </div>
        <input type="hidden" name="_aegis_typing_ms" value="0">
        <input type="hidden" name="_aegis_keystrokes" value="0">
        <input type="hidden" name="_aegis_pastes" value="0">
        <input type="hidden" name="_aegis_uk_screen_ack" value="${document.cookie.includes('aegis_uk_screen_ack=1') ? '1' : '0'}">
      `);

      form.addEventListener('submit', () => {
        const typingInput = form.querySelector('[name="_aegis_typing_ms"]');
        const keyInput = form.querySelector('[name="_aegis_keystrokes"]');
        const pasteInput = form.querySelector('[name="_aegis_pastes"]');
        if (typingInput) typingInput.value = Math.round(performance.now() - startTs);
        if (keyInput) keyInput.value = keystrokes;
        if (pasteInput) pasteInput.value = pastes;
      });
    });
  }

  document.getElementById('aegis-ack-btn')?.addEventListener('click', () => {
    document.cookie = 'aegis_uk_screen_ack=1; path=/; max-age=<?= $retention * 86400 ?>; SameSite=Lax';
    document.querySelectorAll('[name="_aegis_uk_screen_ack"]').forEach(el => el.value = '1');
    const banner = document.getElementById('aegis-uk-security-banner');
    if (banner) banner.style.display = 'none';
  });

  if (document.cookie.includes('aegis_uk_screen_ack=1')) {
    const banner = document.getElementById('aegis-uk-security-banner');
    if (banner) banner.style.display = 'none';
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bindProtectedForms);
  } else {
    bindProtectedForms();
  }
})();
</script>
