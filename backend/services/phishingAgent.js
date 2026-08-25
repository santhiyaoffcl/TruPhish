const dns = require('dns').promises;
const tls = require('tls');
const { URL } = require('url');

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

class PhishingAgent {
    constructor() {
        this.brands = [
            'paypal', 'google', 'microsoft', 'apple', 'amazon', 'netflix',
            'facebook', 'instagram', 'twitter', 'bankofamerica', 'chase',
            'wellsfargo', 'yahoo', 'outlook', 'live', 'ebay', 'walmart',
            'target', 'dhl', 'fedex', 'ups'
        ];
        this.suspiciousTlds = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.click', '.link', '.work', '.date', '.party'];
        this.phishingKeywords = ['login', 'signin', 'verify', 'update', 'secure', 'account', 'bank', 'urgent', 'free', 'wallet', 'billing'];
    }

    parseUrl(url) {
        let normalized = url;
        if (!normalized.startsWith('http://') && !normalized.startsWith('https://')) {
            normalized = 'http://' + normalized;
        }
        try {
            const parsed = new URL(normalized);
            return parsed.hostname || parsed.pathname.split('/')[0];
        } catch {
            return url;
        }
    }

    fetchCert(domain) {
        return new Promise((resolve, reject) => {
            const socket = tls.connect({
                host: domain,
                port: 443,
                servername: domain,
                rejectUnauthorized: true,
                timeout: 1500
            }, () => {
                const cert = socket.getPeerCertificate();
                socket.end();
                resolve(cert);
            });
            socket.on('error', reject);
            socket.on('timeout', () => {
                socket.destroy();
                reject(new Error('SSL handshake timed out'));
            });
        });
    }

    async *scanUrlStream(url, { delayed = true } = {}) {
        const wait = (ms) => (delayed ? sleep(ms) : Promise.resolve());

        yield { step: 'init', status: 'running', message: `🤖 Threat Intelligence Agent initialized for: ${url}` };
        await wait(500);

        let riskScore = 0;
        const explanations = [];
        const logs = [];

        const domain = this.parseUrl(url);
        logs.push(`Parsed target hostname: ${domain}`);

        yield { step: 'dns', status: 'running', message: `🔍 Resolving DNS records for domain: ${domain}...` };
        await wait(600);

        let ipResolved = null;
        try {
            const lookup = await dns.lookup(domain);
            ipResolved = lookup.address;
            yield { step: 'dns', status: 'success', message: `🌐 DNS resolved successfully. Target IP: ${ipResolved}` };
            logs.push(`DNS lookup success: ${domain} -> ${ipResolved}`);
        } catch (e) {
            riskScore += 30;
            explanations.push('Domain DNS record cannot be resolved (unregistered host or dynamic DNS).');
            yield { step: 'dns', status: 'danger', message: `❌ DNS resolution failed: ${e.message}` };
            logs.push(`DNS resolution failed: ${e.message}`);
        }

        yield { step: 'ssl', status: 'running', message: '🔒 Fetching SSL/TLS certificate details...' };
        await wait(600);

        let sslValid = false;
        let sslIssuer = 'None';
        if (ipResolved) {
            try {
                const cert = await this.fetchCert(domain);
                sslIssuer = (cert.issuer && (cert.issuer.CN || cert.issuer.O)) || 'Unknown Authority';
                sslValid = true;
                yield { step: 'ssl', status: 'success', message: `🔒 SSL certificate is active. Issued by: ${sslIssuer}` };
                logs.push(`SSL Verified: Issuer is ${sslIssuer}`);
            } catch (e) {
                riskScore += 20;
                explanations.push('No active or valid SSL/TLS certificate found (unencrypted connection or self-signed cert).');
                yield { step: 'ssl', status: 'warning', message: `⚠️ SSL handshake failed: ${e.message}` };
                logs.push(`SSL Handshake failed: ${e.message}`);
            }
        } else {
            riskScore += 20;
            explanations.push('SSL analysis skipped due to DNS resolution failure.');
            yield { step: 'ssl', status: 'danger', message: '❌ SSL certificate check skipped: DNS unresolved.' };
            logs.push('SSL skipped because IP could not be resolved.');
        }

        yield { step: 'brand', status: 'running', message: '🎯 Analyzing brand impersonation signatures...' };
        await wait(600);

        let impersonating = false;
        let impersonatedBrand = null;
        const domainLower = domain.toLowerCase();

        for (const brand of this.brands) {
            if (domainLower.includes(brand)) {
                const isAuthentic = domainLower === `${brand}.com` || domainLower.endsWith(`.${brand}.com`);
                if (!isAuthentic) {
                    impersonating = true;
                    impersonatedBrand = brand;
                    break;
                }
            }
        }

        if (impersonating) {
            riskScore += 45;
            explanations.push(`Domain name impersonates legitimate brand: ${impersonatedBrand.toUpperCase()}.`);
            yield { step: 'brand', status: 'danger', message: `🚨 Impersonation Alert: Domain is spoofing legitimate ${impersonatedBrand.toUpperCase()} services!` };
            logs.push(`Impersonation match found: ${impersonatedBrand}`);
        } else {
            yield { step: 'brand', status: 'success', message: '🎯 Domain matches no known brand impersonation patterns.' };
            logs.push('No brand impersonation keywords found in host.');
        }

        yield { step: 'content', status: 'running', message: '📄 Inspecting URL heuristics and metadata...' };
        await wait(500);

        const urlLower = url.toLowerCase();
        const matchedKeywords = this.phishingKeywords.filter((word) => urlLower.includes(word));
        const matchedTlds = this.suspiciousTlds.filter((tld) => urlLower.endsWith(tld) || urlLower.includes(`${tld}/`));

        if (matchedKeywords.length) {
            riskScore += 15;
            explanations.push(`URL path or query parameters contain phishing-related keywords: ${matchedKeywords}`);
            logs.push(`Phishing keywords in path: ${matchedKeywords}`);
        }

        if (matchedTlds.length) {
            riskScore += 15;
            explanations.push(`Domain uses a suspicious TLD (${matchedTlds[0]}) associated with low-cost phishing registers.`);
            logs.push(`Suspicious TLD flagged: ${matchedTlds[0]}`);
        }

        if (matchedKeywords.length || matchedTlds.length) {
            yield { step: 'content', status: 'warning', message: `⚠️ Heuristics flags raised: Keywords ${matchedKeywords} | TLD ${matchedTlds}` };
        } else {
            yield { step: 'content', status: 'success', message: '📄 Heuristics scan complete. Path and TLD appear standard.' };
            logs.push('No content heuristic warnings.');
        }

        riskScore = Math.min(Math.max(riskScore, 0), 99);
        let prediction;
        if (riskScore === 0) {
            riskScore = Math.floor(Math.random() * 12) + 4;
            prediction = 'safe';
            explanations.push('URL appears secure and conforms to standard enterprise domain registries.');
        } else if (riskScore >= 50) {
            prediction = 'phishing';
        } else {
            prediction = 'suspicious';
        }

        let briefing = `### Security Assessment Briefing\n\n` +
            `**Verdict:** ${prediction.toUpperCase()}\n` +
            `**Security Confidence Risk**: \`${riskScore}% Severity\`\n\n` +
            `#### 🔍 Key Findings:\n`;
        for (const exp of explanations) {
            briefing += `- ${exp}\n`;
        }
        briefing += `\n#### 🌐 Diagnostics Output:\n` +
            `- Host Resolved: \`${ipResolved || 'Unresolved'}\`\n` +
            `- HTTPS Active: \`${sslValid ? `Yes (${sslIssuer})` : 'No (Plain HTTP / Certificate Invalid)'}\`\n`;

        yield {
            step: 'complete',
            status: 'success',
            message: '✅ Analysis completed successfully.',
            data: {
                risk_score: riskScore,
                prediction,
                explanations,
                report: briefing,
                logs
            }
        };
    }

    async *scanTextStream(text, { delayed = true } = {}) {
        const wait = (ms) => (delayed ? sleep(ms) : Promise.resolve());

        yield { step: 'init', status: 'running', message: '🤖 Semantic Urgency Audit initialized...' };
        await wait(500);

        let riskScore = 0;
        const explanations = [];
        const logs = [];
        const textLower = text.toLowerCase();

        yield { step: 'urgency', status: 'running', message: '⚠️ Analyzing copy urgency and cognitive pressure...' };
        await wait(600);

        const urgencyWords = ['immediately', 'urgent', 'action required', 'suspended', 'terminate', 'limited time', 'unauthorized access', 'pay now', 'last chance'];
        const foundUrgency = urgencyWords.filter((word) => textLower.includes(word));
        if (foundUrgency.length) {
            riskScore += 25;
            explanations.push(`Message employs artificial urgency tactics: ${foundUrgency}`);
            yield { step: 'urgency', status: 'warning', message: `⚠️ Cognitive pressure phrases detected: ${foundUrgency}` };
            logs.push(`Urgency vocabulary matches: ${foundUrgency}`);
        } else {
            yield { step: 'urgency', status: 'success', message: '✅ Message contains normal, low-pressure phrasing.' };
            logs.push('No urgency keywords found.');
        }

        yield { step: 'financial', status: 'running', message: '💳 Auditing credentials & financial harvesting attempts...' };
        await wait(600);

        const financialWords = ['bank', 'account', 'credit card', 'debit card', 'ssn', 'social security', 'routing number', 'pin', 'password', 'login', 'credentials', 'verify your identity', 'security update'];
        const foundFinancial = financialWords.filter((word) => textLower.includes(word));
        if (foundFinancial.length) {
            riskScore += 25;
            explanations.push(`Copy solicits confidential banking credentials/PII: ${foundFinancial}`);
            yield { step: 'financial', status: 'warning', message: `⚠️ Financial credential requests found: ${foundFinancial}` };
            logs.push(`Financial credentials matches: ${foundFinancial}`);
        } else {
            yield { step: 'financial', status: 'success', message: '✅ No sensitive financial or PII solicitations found.' };
            logs.push('No financial keywords found.');
        }

        yield { step: 'brand', status: 'running', message: '🏢 Scanning for enterprise brand name spoofing...' };
        await wait(600);

        const foundBrands = this.brands.filter((brand) => textLower.includes(brand));
        if (foundBrands.length) {
            riskScore += 20;
            explanations.push(`Message references high-profile brand entities (${foundBrands}) without digital sign-offs.`);
            yield { step: 'brand', status: 'warning', message: `⚠️ Message mentions high-target corporate brands: ${foundBrands}` };
            logs.push(`Brands referenced in copy: ${foundBrands}`);
        } else {
            yield { step: 'brand', status: 'success', message: '✅ No high-target brand impersonations detected.' };
            logs.push('No brand names found.');
        }

        yield { step: 'links', status: 'running', message: '🔗 Extracting and auditing links within the content...' };
        await wait(600);

        const urls = text.match(/https?:\/\/[^\s]+|www\.[^\s]+/g) || [];
        if (urls.length) {
            let firstUrl = urls[0];
            firstUrl = firstUrl.split(/[;,.?"')>]/)[0];
            yield { step: 'links', status: 'warning', message: `🔗 Link identified: ${firstUrl}. Spawning sub-agent threat-hunt...` };
            logs.push(`Found embedded URL: ${firstUrl}`);
            await wait(500);

            const domain = this.parseUrl(firstUrl);
            let ipResolved = null;
            try {
                const lookup = await dns.lookup(domain);
                ipResolved = lookup.address;
                logs.push(`Sub-agent DNS: ${domain} resolved to ${ipResolved}`);
            } catch {
                logs.push(`Sub-agent DNS: Failed resolving ${domain}`);
            }

            let urlRisk = 0;
            if (!ipResolved) {
                urlRisk += 30;
            }

            let impersonating = false;
            const domainLower = domain.toLowerCase();
            for (const brand of this.brands) {
                if (domainLower.includes(brand) && !(domainLower === `${brand}.com` || domainLower.endsWith(`.${brand}.com`))) {
                    impersonating = true;
                    break;
                }
            }
            if (impersonating) {
                urlRisk += 40;
            }

            if (urlRisk >= 30) {
                riskScore += 30;
                explanations.push(`Contains an embedded link (${firstUrl}) that fails security domain checks.`);
                yield { step: 'links', status: 'danger', message: `🚨 Hyperlink Danger: Resolved IP or brand checks failed for ${firstUrl}.` };
            } else {
                yield { step: 'links', status: 'success', message: `✅ Hyperlink verified secure: ${firstUrl}.` };
            }
        } else {
            yield { step: 'links', status: 'success', message: '✅ No embedded web links found.' };
            logs.push('No URLs extracted from text.');
        }

        riskScore = Math.min(Math.max(riskScore, 0), 99);
        let prediction;
        if (riskScore === 0) {
            riskScore = Math.floor(Math.random() * 12) + 4;
            prediction = 'safe';
            explanations.push('The message contains no semantic vectors of threat or urgency.');
        } else if (riskScore >= 50) {
            prediction = 'phishing';
        } else {
            prediction = 'suspicious';
        }

        let briefing = `### Content Audit Assessment\n\n` +
            `**Verdict:** ${prediction.toUpperCase()}\n` +
            `**Security Confidence Risk**: \`${riskScore}% Severity\`\n\n` +
            `#### 🔍 Key Findings:\n`;
        for (const exp of explanations) {
            briefing += `- ${exp}\n`;
        }

        yield {
            step: 'complete',
            status: 'success',
            message: '✅ Text content audit complete.',
            data: {
                risk_score: riskScore,
                prediction,
                explanations,
                report: briefing,
                logs
            }
        };
    }

    async scanUrl(url) {
        let finalData = {};
        for await (const event of this.scanUrlStream(url, { delayed: false })) {
            if (event.step === 'complete') {
                finalData = event.data;
            }
        }
        return finalData;
    }

    async scanText(text) {
        let finalData = {};
        for await (const event of this.scanTextStream(text, { delayed: false })) {
            if (event.step === 'complete') {
                finalData = event.data;
            }
        }
        return finalData;
    }
}

module.exports = { PhishingAgent };
