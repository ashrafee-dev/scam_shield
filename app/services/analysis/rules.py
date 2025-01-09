"""Scam detection rules registry.

Each DetectionRule is a declarative, testable unit. The engine imports this
list and applies every rule to normalized input text. Rules are organized by
category to make maintenance straightforward.

Weight guidance:
  5  – weak signal, common in legitimate content
  10 – moderate signal
  15 – strong signal
  20 – very strong signal, rarely benign
  25 – near-certain scam indicator
"""

from app.services.analysis.models import DetectionRule

DETECTION_RULES: list[DetectionRule] = [
    # ------------------------------------------------------------------ Urgency
    DetectionRule(
        id="urgency_act_now",
        name="Urgency – Act Now",
        patterns=[
            r"\bact (now|immediately)\b",
            r"\burgent(ly)?\b",
            r"\bimmediately\b",
            r"\bright now\b",
            r"\btime[ -]sensitive\b",
            r"\blast chance\b",
            r"\bfinal notice\b",
            r"\bdon'?t delay\b",
            r"\brespond (now|immediately|today)\b",
            r"\bwithin (24|48|72) hours?\b",
            r"\btoday only\b",
            r"\bexpires? (today|soon|shortly)\b",
        ],
        weight=15,
        category="urgency",
        reason="Urgency language used to pressure the target into acting without thinking",
    ),
    # ---------------------------------------------------------------- Fear / Threat
    DetectionRule(
        id="fear_threat_language",
        name="Fear / Threat Language",
        patterns=[
            r"\byour account (will be|has been|is being) (suspend|terminat|clos|block|lock)",
            r"\bsuspended\b",
            r"\blegal action\b",
            r"\blawsuit\b",
            r"\bwarrant\b",
            r"\barrest(ed)?\b",
            r"\blaw enforcement\b",
            r"\bcriminal charges?\b",
            r"\bprosecut(e|ion)\b",
            r"\bdebt collect\b",
            r"\byou (will|are going to) be (arrested|prosecuted|charged)\b",
            r"\bimminent (action|threat|arrest)\b",
        ],
        weight=20,
        category="legal threat",
        reason="Fear or legal-threat language designed to intimidate the target",
    ),
    # -------------------------------------------------------- Account Suspension
    DetectionRule(
        id="account_suspension",
        name="Account Suspension Warning",
        patterns=[
            r"\baccount (is|has been|will be) (suspend|terminat|clos|lock|block)",
            r"\bsuspended account\b",
            r"\breactivate your account\b",
            r"\bunusual activity (detected|found|identified)\b",
            r"\bsuspicious (login|activity|access)\b",
            r"\bunauthorized (access|login|activity)\b",
        ],
        weight=15,
        category="account takeover attempt",
        reason="Account suspension language used to trigger fear and compliance",
    ),
    # ---------------------------------------------------- Institution Impersonation
    DetectionRule(
        id="impersonation_bank",
        name="Bank Impersonation",
        patterns=[
            r"\bbank (security|fraud|department|officer|representative)\b",
            r"\byour bank\b",
            r"\bfraud (department|team|unit)\b",
            r"\bfinancial institution\b",
            r"\bchase\b",
            r"\bbank of america\b",
            r"\bwells fargo\b",
            r"\bcitibank\b",
            r"\bcapital one\b",
        ],
        weight=20,
        category="bank impersonation",
        reason="Impersonation of a bank or financial institution",
    ),
    DetectionRule(
        id="impersonation_irs_gov",
        name="IRS / Government Impersonation",
        patterns=[
            r"\bIRS\b",
            r"\binternal revenue service\b",
            r"\bsocial security (administration|office|department|number|benefits)\b",
            r"\bssa\b",
            r"\bgovernment (agency|official|department|representative)\b",
            r"\bdepartment of (treasury|justice|homeland security)\b",
            r"\bfbi\b",
            r"\bdea\b",
            r"\byour (tax|federal) (return|refund|debt|liability)\b",
            r"\btax (lien|levy|debt|fraud)\b",
            r"\bcustoms (and border|officer|official)\b",
        ],
        weight=20,
        category="IRS/government impersonation",
        reason="Impersonation of the IRS, SSA, or a government agency",
    ),
    DetectionRule(
        id="impersonation_tech_support",
        name="Tech Support Impersonation",
        patterns=[
            r"\bmicrosoft (support|security|helpdesk|technician)\b",
            r"\bwindows (support|security|technician|department)\b",
            r"\bapple (support|security|helpdesk|care)\b",
            r"\bamazon (support|security|helpdesk|prime)\b",
            r"\bgoogle (support|security|helpdesk)\b",
            r"\btech(nical)? support\b",
            r"\bcomputer (infected|compromised|hacked|virus)\b",
            r"\byour (computer|device|pc) (has|is|was) (infected|hacked|compromised|at risk)\b",
            r"\bremote (access|session|assistance|desktop)\b",
            r"\bteamviewer\b",
            r"\banydesk\b",
        ],
        weight=20,
        category="tech support scam",
        reason="Tech support impersonation or remote access solicitation",
    ),
    # -------------------------------------------------------- OTP / Verification
    DetectionRule(
        id="otp_code_request",
        name="OTP / Verification Code Request",
        patterns=[
            r"\bread (me|us|out) the (code|number|pin|otp)\b",
            r"\bverification code\b",
            r"\bone[ -]time (password|code|pin)\b",
            r"\botp\b",
            r"\bsms code\b",
            r"\bsecurity code\b",
            r"\bconfirmation code\b",
            r"\benter the code\b",
            r"\bwhat('?s| is) the code\b",
            r"\bthe code (sent|texted|messaged) to you\b",
            r"\b6[ -]digit code\b",
        ],
        weight=25,
        category="OTP theft",
        reason="Request for a one-time password or verification code — a strong sign of account takeover",
    ),
    # -------------------------------------------------------- Sensitive Info
    DetectionRule(
        id="sensitive_info_request",
        name="Sensitive Information Request",
        patterns=[
            r"\bsocial security number\b",
            r"\bssn\b",
            r"\bdate of birth\b",
            r"\bmother'?s maiden name\b",
            r"\bcredit card (number|details|info)\b",
            r"\bcard (number|details|cvv|expiry|pin)\b",
            r"\bbank (account|routing) number\b",
            r"\bconfirm your (password|pin|credentials|identity|ssn|dob)\b",
            r"\bverify your (identity|account|information|details|ssn)\b",
            r"\bprovide your (personal|bank|account|card) (details|information|number)\b",
            r"\bfull (name|address|ssn|date of birth)\b",
        ],
        weight=20,
        category="phishing",
        reason="Request for sensitive personal or financial information",
    ),
    # --------------------------------------------------------- Payment Fraud
    DetectionRule(
        id="payment_gift_card",
        name="Gift Card Payment Request",
        patterns=[
            r"\bgift card(s)?\b",
            r"\bitunes (card|gift)\b",
            r"\bgoogle play (card|gift)\b",
            r"\bamazon gift card\b",
            r"\bsteam (card|gift)\b",
            r"\bpay (with|using|via|by|through) (a |gift)?(card)\b",
            r"\bbuy (a |some )?(gift card|cards)\b",
        ],
        weight=25,
        category="payment fraud",
        reason="Gift card payment is a hallmark of fraud — no legitimate organization requests gift card payment",
    ),
    DetectionRule(
        id="payment_crypto",
        name="Cryptocurrency Payment Request",
        patterns=[
            r"\bcrypto(currency)? (payment|transfer|wallet|address)\b",
            r"\bbitcoin\b",
            r"\bethereum\b",
            r"\busdt\b",
            r"\bcrypto atm\b",
            r"\bsend (bitcoin|crypto|eth|btc)\b",
            r"\bcoinbase\b",
            r"\bwallet address\b",
        ],
        weight=20,
        category="payment fraud",
        reason="Cryptocurrency payment request — commonly used by scammers to avoid chargebacks",
    ),
    DetectionRule(
        id="payment_wire_transfer",
        name="Wire Transfer Request",
        patterns=[
            r"\bwire transfer\b",
            r"\bbank transfer\b",
            r"\bzelle\b",
            r"\bvenmo\b",
            r"\bcash app\b",
            r"\bwestern union\b",
            r"\bmoneygram\b",
            r"\btransfer (the|your) (money|funds|payment|balance)\b",
            r"\bsend (the|your) (money|funds|payment)\b",
        ],
        weight=15,
        category="payment fraud",
        reason="Wire transfer or peer-to-peer payment request — frequently used in scams",
    ),
    # -------------------------------------------------------- Suspicious Links
    DetectionRule(
        id="suspicious_link",
        name="Suspicious Link",
        patterns=[
            r"\bclick (this|the|here|below) link\b",
            r"\bclick here\b",
            r"\bfollow (this|the) link\b",
            r"\bvisit (this|the) (link|url|website|site|page)\b",
            r"\bopen (this|the) link\b",
            r"http[s]?://[^\s]*\.(ru|cn|tk|ml|ga|cf|gq|pw|top|click|download|zip|review)\b",
            r"http[s]?://[^\s]*[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",
        ],
        weight=15,
        category="phishing",
        reason="Suspicious link or prompt to click a link — potential phishing vector",
    ),
    # -------------------------------------------------------- Refund Scam
    DetectionRule(
        id="refund_scam",
        name="Refund / Overpayment Scam",
        patterns=[
            r"\brefund (is|has been|was) (processed|approved|sent|issued)\b",
            r"\byou('?re| are) (entitled|owed|due) (a |to a )?refund\b",
            r"\boverpaid\b",
            r"\bover(payment|charge)d?\b",
            r"\bwe accidentally (sent|transferred|deposited)\b",
            r"\bsend (back|the difference|the excess|the overpayment)\b",
        ],
        weight=20,
        category="payment fraud",
        reason="Refund or overpayment scam language — designed to trick victims into sending money",
    ),
    # -------------------------------------------------------- Remote Access
    DetectionRule(
        id="remote_access_scam",
        name="Remote Access Solicitation",
        patterns=[
            r"\bdownload (this|the|our) (software|app|tool|program)\b",
            r"\binstall (this|the|our) (software|app|tool|program)\b",
            r"\bgive (me|us) (access|control|permission)\b",
            r"\ballow (me|us) to (access|connect|control)\b",
            r"\bshare (your|the) (screen|desktop)\b",
            r"\bscreen share\b",
            r"\bremote (access|control|session|desktop|assistance)\b",
            r"\bteamviewer\b",
            r"\banydesk\b",
            r"\blogmein\b",
        ],
        weight=20,
        category="tech support scam",
        reason="Remote access request — commonly used to steal data or install malware",
    ),
    # -------------------------------------------------------- Password Request
    DetectionRule(
        id="password_request",
        name="Password / Credential Request",
        patterns=[
            r"\bconfirm your password\b",
            r"\benter your password\b",
            r"\bprovide your (login|password|credentials)\b",
            r"\bwhat('?s| is) your password\b",
            r"\byour (login|username|password|credentials)\b",
            r"\breset (link|your password)\b",
        ],
        weight=20,
        category="phishing",
        reason="Direct request for password or credentials",
    ),
    # -------------------------------------------------------- Lottery / Prize
    DetectionRule(
        id="lottery_prize",
        name="Lottery / Prize Scam",
        patterns=[
            r"\byou (have|'?ve) (won|been selected|been chosen)\b",
            r"\bcongratulations.{0,30}(won|winner|prize|selected)\b",
            r"\blottery\b",
            r"\bsweepstakes\b",
            r"\bprize (money|claim|winner)\b",
            r"\bclaim your (prize|winnings|reward)\b",
            r"\bunclaimed (prize|reward|money|funds)\b",
        ],
        weight=15,
        category="lottery/prize scam",
        reason="Lottery or prize scam language — typically requires upfront payment or personal info",
    ),
    # -------------------------------------------------------- Manipulation Cues
    DetectionRule(
        id="manipulation_secrecy",
        name="Secrecy / Isolation Cue",
        patterns=[
            r"\bdon'?t tell (anyone|your family|your spouse|your bank)\b",
            r"\bkeep (this|it) (between us|confidential|secret|private)\b",
            r"\bdo not (contact|call|speak to) (your bank|the police|anyone)\b",
            r"\bdon'?t (hang up|call back|contact)\b",
            r"\btrust (me|us|only)\b",
        ],
        weight=20,
        category="manipulation",
        reason="Secrecy or isolation cue — designed to prevent the victim from seeking help",
    ),
    DetectionRule(
        id="manipulation_authority",
        name="False Authority / Pressure",
        patterns=[
            r"\bthis is (a |an )?(official|final|last) (notice|warning|call)\b",
            r"\bofficial (call|notice|warning|communication)\b",
            r"\byou are (legally|formally|officially) required\b",
            r"\bfailure to (comply|respond|act|cooperate)\b",
            r"\bdo not (ignore|disregard) this\b",
        ],
        weight=15,
        category="manipulation",
        reason="False authority or official-sounding pressure language",
    ),
]

# Lookup table for fast access by rule ID
RULE_BY_ID: dict[str, DetectionRule] = {r.id: r for r in DETECTION_RULES}
