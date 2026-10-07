/* =========================================
   PHISHGUARD
   Phishing URL Detection System
   Rule-Based URL Analyzer
   ========================================= */


/* ---------- DOM ELEMENTS ---------- */

const urlInput = document.getElementById("urlInput");
const analyzeBtn = document.getElementById("analyzeBtn");
const clearBtn = document.getElementById("clearBtn");

const loading = document.getElementById("loading");
const errorMessage = document.getElementById("errorMessage");
const errorText = document.getElementById("errorText");

const resultsSection = document.getElementById("resultsSection");

const resultIcon = document.getElementById("resultIcon");
const resultTitle = document.getElementById("resultTitle");
const resultDescription = document.getElementById("resultDescription");

const riskScore = document.getElementById("riskScore");
const riskBar = document.getElementById("riskBar");

const analyzedUrl = document.getElementById("analyzedUrl");

const checksContainer =
    document.getElementById("checksContainer");

const riskFactorsCard =
    document.getElementById("riskFactorsCard");

const riskFactors =
    document.getElementById("riskFactors");

const scanAgainBtn =
    document.getElementById("scanAgainBtn");

const historyContainer =
    document.getElementById("historyContainer");

const clearHistoryBtn =
    document.getElementById("clearHistoryBtn");


/* ---------- SUSPICIOUS KEYWORDS ---------- */

const suspiciousKeywords = [
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "secure",
    "security",
    "update",
    "confirm",
    "confirmation",
    "password",
    "credential",
    "bank",
    "banking",
    "wallet",
    "payment",
    "invoice",
    "bonus",
    "free",
    "reward",
    "claim",
    "urgent",
    "suspend",
    "unlock",
    "authenticate",
    "webscr",
    "microsoft-login",
    "paypal-login"
];


/* ---------- URL SHORTENERS ---------- */

const shortenerDomains = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "cutt.ly",
    "shorturl.at",
    "rebrand.ly"
];


/* ---------- EVENT LISTENERS ---------- */

analyzeBtn.addEventListener("click", analyzeURL);

clearBtn.addEventListener("click", clearInput);

scanAgainBtn.addEventListener("click", resetScanner);

clearHistoryBtn.addEventListener("click", clearHistory);


/* Analyze when Enter is pressed */

urlInput.addEventListener("keydown", function (event) {

    if (event.key === "Enter") {
        analyzeURL();
    }

});


/* Remove error while typing */

urlInput.addEventListener("input", function () {

    hideError();

});


/* ---------- MAIN ANALYSIS ---------- */

function analyzeURL() {

    let input = urlInput.value.trim();

    hideError();

    if (!input) {

        showError("Please enter a website URL.");

        urlInput.focus();

        return;
    }


    /*
     * Add HTTPS automatically when the user
     * enters a domain without a protocol.
     */

    let normalizedURL = input;

    if (!/^https?:\/\//i.test(normalizedURL)) {

        normalizedURL = "https://" + normalizedURL;

    }


    let url;

    try {

        url = new URL(normalizedURL);

    } catch (error) {

        showError(
            "Invalid URL. Please enter a valid website address."
        );

        return;
    }


    /* Only allow HTTP and HTTPS */

    if (
        url.protocol !== "http:" &&
        url.protocol !== "https:"
    ) {

        showError(
            "Only HTTP and HTTPS website URLs are supported."
        );

        return;
    }


    /* Show loading */

    loading.classList.remove("hidden");

    analyzeBtn.disabled = true;


    /*
     * Small delay makes the scanner feel like
     * a real security analysis process.
     */

    setTimeout(function () {

        const analysis = analyzeURLFeatures(url);

        displayResults(
            analysis,
            normalizedURL
        );

        saveScan(
            normalizedURL,
            analysis
        );

        loading.classList.add("hidden");

        analyzeBtn.disabled = false;

    }, 650);

}


/* =========================================
   URL FEATURE ANALYSIS
   ========================================= */

function analyzeURLFeatures(url) {

    let score = 0;

    const checks = [];

    const risks = [];


    /* ---------- HTTPS ---------- */

    if (url.protocol === "https:") {

        checks.push({
            name: "HTTPS Encryption",
            detail: "Secure HTTPS connection detected",
            status: "safe",
            icon: "🔒"
        });

    } else {

        score += 12;

        checks.push({
            name: "HTTPS Encryption",
            detail: "Website does not use HTTPS",
            status: "danger",
            icon: "🔓"
        });

        risks.push(
            "The URL does not use HTTPS encryption."
        );

    }


    /* ---------- URL LENGTH ---------- */

    const length = url.href.length;

    if (length <= 75) {

        checks.push({
            name: "URL Length",
            detail: `${length} characters — normal`,
            status: "safe",
            icon: "📏"
        });

    } else if (length <= 120) {

        score += 8;

        checks.push({
            name: "URL Length",
            detail: `${length} characters — somewhat long`,
            status: "warning",
            icon: "📏"
        });

        risks.push(
            "The URL is unusually long."
        );

    } else {

        score += 18;

        checks.push({
            name: "URL Length",
            detail: `${length} characters — very long`,
            status: "danger",
            icon: "📏"
        });

        risks.push(
            "The URL is excessively long, which can hide suspicious content."
        );

    }


    /* ---------- IP ADDRESS ---------- */

    const hostname = url.hostname;

    const ipPattern =
        /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;


    if (ipPattern.test(hostname)) {

        score += 25;

        checks.push({
            name: "IP Address Host",
            detail: "Website uses an IP address instead of a domain",
            status: "danger",
            icon: "🌐"
        });

        risks.push(
            "The website uses an IP address instead of a normal domain name."
        );

    } else {

        checks.push({
            name: "IP Address Host",
            detail: "Normal domain name detected",
            status: "safe",
            icon: "🌐"
        });

    }


    /* ---------- @ SYMBOL ---------- */

    if (url.href.includes("@")) {

        score += 20;

        checks.push({
            name: "@ Symbol",
            detail: "Suspicious @ symbol detected",
            status: "danger",
            icon: "@"
        });

        risks.push(
            "The URL contains an @ symbol, which can be used to disguise the real destination."
        );

    } else {

        checks.push({
            name: "@ Symbol",
            detail: "No suspicious @ symbol",
            status: "safe",
            icon: "@"
        });

    }


    /* ---------- SUBDOMAINS ---------- */

    const domainParts = hostname.split(".");

    const subdomainCount =
        Math.max(0, domainParts.length - 2);


    if (subdomainCount === 0) {

        checks.push({
            name: "Subdomain Structure",
            detail: "Normal domain structure",
            status: "safe",
            icon: "🌳"
        });

    } else if (subdomainCount === 1) {

        score += 3;

        checks.push({
            name: "Subdomain Structure",
            detail: "1 subdomain detected",
            status: "safe",
            icon: "🌳"
        });

    } else if (subdomainCount === 2) {

        score += 8;

        checks.push({
            name: "Subdomain Structure",
            detail: `${subdomainCount} subdomains detected`,
            status: "warning",
            icon: "🌳"
        });

        risks.push(
            "Multiple subdomains were detected."
        );

    } else {

        score += 15;

        checks.push({
            name: "Subdomain Structure",
            detail: `${subdomainCount} subdomains detected`,
            status: "danger",
            icon: "🌳"
        });

        risks.push(
            "The URL contains an unusually large number of subdomains."
        );

    }


    /* ---------- SUSPICIOUS KEYWORDS ---------- */

    const fullURL = url.href.toLowerCase();

    const foundKeywords = suspiciousKeywords.filter(
        keyword => fullURL.includes(keyword)
    );


    if (foundKeywords.length === 0) {

        checks.push({
            name: "Suspicious Keywords",
            detail: "No common phishing keywords detected",
            status: "safe",
            icon: "🔍"
        });

    } else {

        const keywordScore =
            Math.min(foundKeywords.length * 5, 20);

        score += keywordScore;


        checks.push({
            name: "Suspicious Keywords",
            detail:
                `${foundKeywords.length} keyword(s) detected`,
            status:
                foundKeywords.length >= 3
                    ? "danger"
                    : "warning",
            icon: "🔍"
        });


        risks.push(
            "Suspicious keywords detected: " +
            foundKeywords.join(", ") +
            "."
        );

    }


    /* ---------- URL SHORTENER ---------- */

    const lowerHostname =
        hostname.toLowerCase();


    const isShortener =
        shortenerDomains.some(
            domain =>
                lowerHostname === domain ||
                lowerHostname.endsWith("." + domain)
        );


    if (isShortener) {

        score += 15;

        checks.push({
            name: "URL Shortener",
            detail: "Known URL-shortening service detected",
            status: "warning",
            icon: "🔗"
        });

        risks.push(
            "The URL uses a shortening service, which can hide the final destination."
        );

    } else {

        checks.push({
            name: "URL Shortener",
            detail: "No known URL shortener detected",
            status: "safe",
            icon: "🔗"
        });

    }


    /* ---------- PUNYCODE ---------- */

    if (hostname.includes("xn--")) {

        score += 20;

        checks.push({
            name: "Internationalized Domain",
            detail: "Punycode domain detected",
            status: "danger",
            icon: "🌍"
        });

        risks.push(
            "The domain uses Punycode, which can sometimes be involved in look-alike domain attacks."
        );

    } else {

        checks.push({
            name: "Internationalized Domain",
            detail: "No Punycode detected",
            status: "safe",
            icon: "🌍"
        });

    }


    /* ---------- HYPHENS ---------- */

    const hyphenCount =
        (hostname.match(/-/g) || []).length;


    if (hyphenCount === 0) {

        checks.push({
            name: "Domain Formatting",
            detail: "No excessive hyphens",
            status: "safe",
            icon: "➖"
        });

    } else if (hyphenCount <= 2) {

        score += 2;

        checks.push({
            name: "Domain Formatting",
            detail: `${hyphenCount} hyphen(s) detected`,
            status: "safe",
            icon: "➖"
        });

    } else {

        score += 8;

        checks.push({
            name: "Domain Formatting",
            detail: `${hyphenCount} hyphens detected`,
            status: "warning",
            icon: "➖"
        });

        risks.push(
            "The domain contains several hyphens."
        );

    }


    /* ---------- SPECIAL CHARACTERS ---------- */

    const specialCharacters =
        (url.pathname + url.search)
            .match(/[!$^*'{}[\]|<>]/g);


    const specialCount =
        specialCharacters
            ? specialCharacters.length
            : 0;


    if (specialCount === 0) {

        checks.push({
            name: "Special Characters",
            detail: "No unusual special characters",
            status: "safe",
            icon: "✳️"
        });

    } else if (specialCount <= 2) {

        score += 4;

        checks.push({
            name: "Special Characters",
            detail: `${specialCount} unusual character(s)`,
            status: "warning",
            icon: "✳️"
        });

    } else {

        score += 10;

        checks.push({
            name: "Special Characters",
            detail: `${specialCount} unusual characters`,
            status: "danger",
            icon: "✳️"
        });

        risks.push(
            "Several unusual special characters were detected."
        );

    }


    /* ---------- PORT ---------- */

    if (url.port) {

        score += 8;

        checks.push({
            name: "Custom Port",
            detail: `Port ${url.port} detected`,
            status: "warning",
            icon: "🔌"
        });

        risks.push(
            `The URL uses a non-default port (${url.port}).`
        );

    } else {

        checks.push({
            name: "Custom Port",
            detail: "No custom port detected",
            status: "safe",
            icon: "🔌"
        });

    }


    /* ---------- EXCESSIVE DOTS ---------- */

    const dotCount =
        (hostname.match(/\./g) || []).length;


    if (dotCount > 4) {

        score += 10;

        risks.push(
            "The hostname contains an unusually high number of dots."
        );

    }


    /* ---------- REPEATED CHARACTERS ---------- */

    if (/([a-z0-9])\1{3,}/i.test(hostname)) {

        score += 8;

        risks.push(
            "The domain contains repeated characters that may indicate suspicious formatting."
        );

    }


    /* ---------- FINAL SCORE ---------- */

    score = Math.min(100, Math.round(score));


    let classification;

    if (score < 25) {

        classification = "safe";

    } else if (score < 55) {

        classification = "warning";

    } else {

        classification = "danger";

    }


    return {
        score,
        classification,
        checks,
        risks
    };

}


/* =========================================
   DISPLAY RESULTS
   ========================================= */

function displayResults(analysis, url) {

    resultsSection.classList.remove("hidden");


    /* URL */

    analyzedUrl.textContent = url;


    /* Score */

    animateScore(
        analysis.score
    );


    /* Risk bar */

    riskBar.style.width =
        analysis.score + "%";


    /* Classification */

    if (analysis.classification === "safe") {

        resultIcon.textContent = "✅";

        resultTitle.textContent =
            "Low Risk — Likely Legitimate";

        resultDescription.textContent =
            "No major suspicious indicators were detected in this URL.";

        resultIcon.style.background =
            "rgba(49, 233, 129, 0.10)";

        riskBar.style.background =
            "#31e981";

    } else if (
        analysis.classification === "warning"
    ) {

        resultIcon.textContent = "⚠️";

        resultTitle.textContent =
            "Medium Risk — Suspicious URL";

        resultDescription.textContent =
            "Some suspicious characteristics were detected. Proceed with caution.";

        resultIcon.style.background =
            "rgba(255, 183, 77, 0.10)";

        riskBar.style.background =
            "#ffb74d";

    } else {

        resultIcon.textContent = "🚨";

        resultTitle.textContent =
            "High Risk — Potential Phishing";

        resultDescription.textContent =
            "Multiple suspicious indicators were detected. Avoid entering sensitive information.";

        resultIcon.style.background =
            "rgba(255, 77, 90, 0.10)";

        riskBar.style.background =
            "#ff5d69";

    }


    /* Security checks */

    checksContainer.innerHTML = "";

    analysis.checks.forEach(
        check => {

            const item =
                document.createElement("div");

            item.className =
                "check-item";

            item.innerHTML = `
                <div class="check-icon ${check.status}">
                    ${check.icon}
                </div>

                <div class="check-content">

                    <div class="check-name">
                        ${escapeHTML(check.name)}
                    </div>

                    <div class="check-detail">
                        ${escapeHTML(check.detail)}
                    </div>

                </div>
            `;

            checksContainer.appendChild(item);

        }
    );


    /* Risk factors */

    riskFactors.innerHTML = "";


    if (analysis.risks.length > 0) {

        riskFactorsCard.classList.remove(
            "hidden"
        );


        analysis.risks.forEach(
            risk => {

                const item =
                    document.createElement("div");

                item.className =
                    "risk-factor";

                item.innerHTML = `
                    <span class="risk-factor-icon">
                        ⚠️
                    </span>

                    <span>
                        ${escapeHTML(risk)}
                    </span>
                `;

                riskFactors.appendChild(item);

            }
        );

    } else {

        riskFactorsCard.classList.add(
            "hidden"
        );

    }


    /* Scroll to result */

    setTimeout(() => {

        resultsSection.scrollIntoView({
            behavior: "smooth",
            block: "start"
        });

    }, 100);

}


/* =========================================
   SCORE ANIMATION
   ========================================= */

function animateScore(targetScore) {

    let current = 0;

    riskScore.textContent = "0";


    const duration = 700;

    const steps = 35;

    const increment =
        targetScore / steps;

    const intervalTime =
        duration / steps;


    const interval =
        setInterval(() => {

            current += increment;


            if (current >= targetScore) {

                current = targetScore;

                clearInterval(interval);

            }


            riskScore.textContent =
                Math.round(current);

        }, intervalTime);

}


/* =========================================
   HISTORY
   ========================================= */

function saveScan(url, analysis) {

    let history =
        JSON.parse(
            localStorage.getItem(
                "phishguardHistory"
            )
        ) || [];


    const scan = {

        url: url,

        score: analysis.score,

        classification:
            analysis.classification,

        date:
            new Date().toLocaleString()

    };


    history.unshift(scan);


    /*
     * Keep only the latest 10 scans.
     */

    history =
        history.slice(0, 10);


    localStorage.setItem(
        "phishguardHistory",
        JSON.stringify(history)
    );


    displayHistory();

}


/* ---------- DISPLAY HISTORY ---------- */

function displayHistory() {

    let history =
        JSON.parse(
            localStorage.getItem(
                "phishguardHistory"
            )
        ) || [];


    if (history.length === 0) {

        historyContainer.innerHTML = `
            <div class="empty-history">

                <div class="empty-icon">
                    🛡️
                </div>

                <p>No scans yet</p>

                <span>
                    Your analyzed URLs will appear here.
                </span>

            </div>
        `;

        return;
    }


    historyContainer.innerHTML = "";


    history.forEach(scan => {

        const item =
            document.createElement("div");

        item.className =
            "history-item";


        let label;

        if (scan.classification === "safe") {

            label = "LOW RISK";

        } else if (
            scan.classification === "warning"
        ) {

            label = "SUSPICIOUS";

        } else {

            label = "PHISHING";

        }


        item.innerHTML = `

            <div>

                <div class="history-url">
                    ${escapeHTML(scan.url)}
                </div>

                <div
                    style="
                        color:#4f5d6e;
                        font-size:9px;
                        margin-top:5px;
                    "
                >
                    ${escapeHTML(scan.date)}
                    • Risk Score: ${scan.score}/100
                </div>

            </div>

            <div class="history-result ${scan.classification}">
                ${label}
            </div>

        `;


        historyContainer.appendChild(item);

    });

}


/* ---------- CLEAR HISTORY ---------- */

function clearHistory() {

    localStorage.removeItem(
        "phishguardHistory"
    );

    displayHistory();

}


/* =========================================
   RESET SCANNER
   ========================================= */

function resetScanner() {

    resultsSection.classList.add(
        "hidden"
    );

    urlInput.value = "";

    hideError();

    urlInput.focus();


    window.scrollTo({

        top: 0,

        behavior: "smooth"

    });

}


/* =========================================
   CLEAR INPUT
   ========================================= */

function clearInput() {

    urlInput.value = "";

    hideError();

    urlInput.focus();

}


/* =========================================
   ERROR HANDLING
   ========================================= */

function showError(message) {

    errorText.textContent = message;

    errorMessage.classList.remove(
        "hidden"
    );

}


function hideError() {

    errorMessage.classList.add(
        "hidden"
    );

}


/* =========================================
   SECURITY HELPER
   ========================================= */

function escapeHTML(value) {

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");

}


/* =========================================
   INITIALIZE
   ========================================= */

displayHistory();
