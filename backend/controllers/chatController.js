const axios = require('axios');
const { PhishingAgent } = require('../services/phishingAgent');

// Help regular expressions
const URL_REGEX = /(https?:\/\/[^\s]+)/gi;
const DOMAIN_REGEX = /\b([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}\b/gi;

exports.handleChat = async (req, res) => {
    try {
        const { message, history, model, agenticDeepSweep } = req.body;

        if (!message) {
            return res.status(400).json({ message: 'Message is required' });
        }

        const selectedModel = model || 'gemini';
        let scanResult = null;
        let scanLogs = [];
        let agentContext = '';

        // 1. Agentic Behavior: Look for domains/URLs to automatically sweep
        const urlsFound = message.match(URL_REGEX);
        const domainsFound = message.match(DOMAIN_REGEX);
        const targetToScan = urlsFound ? urlsFound[0] : (domainsFound ? domainsFound[0] : null);

        if (agenticDeepSweep && targetToScan) {
            try {
                let scanPayload = targetToScan;
                if (!scanPayload.startsWith('http://') && !scanPayload.startsWith('https://')) {
                    scanPayload = 'http://' + scanPayload;
                }

                const agent = new PhishingAgent();
                scanResult = await agent.scanUrl(scanPayload);
                scanLogs = scanResult.logs || [];

                agentContext = `[Agentic Security Tool Output]
Target URL: ${scanPayload}
Calculated Risk: ${scanResult.risk_score}/100 Severity
Prediction: ${scanResult.prediction.toUpperCase()}
Key Findings:
${scanResult.explanations.map(exp => `- ${exp}`).join('\n')}
--------------------------------------------------`;
            } catch (err) {
                console.error('Scanner tool failed:', err.message);
                agentContext = `[Agentic Security Tool Output]
Attempted domain scan for "${targetToScan}" but the Express scan engine failed.
--------------------------------------------------`;
            }
        }

        // 2. Synthesize System Instruction
        const systemPrompt = `You are the TruPhish AI Threat Advisory Agent, an expert cybersecurity analyst.
Your goal is to inspect threat vectors, identify phishing patterns, explain risk factors, and provide defensive recommendations.
Keep your tone authoritative, secure, clear, and professional.`;

        // 3. Dispatch to Selected LLM Model with History
        if (selectedModel === 'gemini') {
            const apiKey = process.env.GEMINI_API_KEY;
            if (apiKey) {
                try {
                    // Map history contents
                    const contents = [];
                    if (Array.isArray(history)) {
                        history.forEach(msg => {
                            // Skip welcome messages
                            if (msg.role === 'assistant' && (msg.id === 'welcome' || msg.content.startsWith('👋'))) return;
                            contents.push({
                                role: msg.role === 'assistant' ? 'model' : 'user',
                                parts: [{ text: msg.content }]
                            });
                        });
                    }

                    // Format current message with tool insights
                    const currentMsgText = `${agentContext ? `${agentContext}\n\n` : ''}${message}`;

                    const systemHeader = `[System Instructions: ${systemPrompt}]\n\n`;

                    if (contents.length === 0) {
                        contents.push({
                            role: 'user',
                            parts: [{ text: systemHeader + currentMsgText }]
                        });
                    } else {
                        // Prepend instruction to first message
                        contents[0].parts[0].text = systemHeader + contents[0].parts[0].text;
                        contents.push({
                            role: 'user',
                            parts: [{ text: currentMsgText }]
                        });
                    }

                    const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`;
                    const geminiRes = await axios.post(geminiUrl, {
                        contents
                    }, { headers: { 'Content-Type': 'application/json' }, timeout: 8000 });

                    const reply = geminiRes.data?.candidates?.[0]?.content?.parts?.[0]?.text;
                    if (reply) {
                        return res.json({
                            reply,
                            modelUsed: 'Google Gemini Pro',
                            toolExecuted: !!scanResult,
                            scanData: scanResult,
                            logs: scanLogs
                        });
                    }
                } catch (geminiErr) {
                    console.error('Gemini API query error:', geminiErr.response?.data || geminiErr.message);
                }
            }
        } else if (selectedModel === 'groq') {
            const apiKey = process.env.GROQ_API_KEY;
            if (apiKey) {
                try {
                    const messages = [];
                    if (Array.isArray(history)) {
                        history.forEach(msg => {
                            if (msg.role === 'assistant' && (msg.id === 'welcome' || msg.content.startsWith('👋'))) return;
                            messages.push({
                                role: msg.role === 'assistant' ? 'assistant' : 'user',
                                content: msg.content
                            });
                        });
                    }

                    // Push system prompt as system message for Groq / OpenAI format
                    messages.unshift({
                        role: 'system',
                        content: systemPrompt
                    });

                    // Push current message
                    messages.push({
                        role: 'user',
                        content: `${agentContext ? `${agentContext}\n\n` : ''}${message}`
                    });

                    const groqRes = await axios.post('https://api.groq.com/openai/v1/chat/completions', {
                        model: 'llama-3.3-70b-versatile',
                        messages
                    }, {
                        headers: {
                            'Authorization': `Bearer ${apiKey}`,
                            'Content-Type': 'application/json'
                        },
                        timeout: 8000
                    });

                    const reply = groqRes.data?.choices?.[0]?.message?.content;
                    if (reply) {
                        return res.json({
                            reply,
                            modelUsed: 'Groq Llama 3.3 70B',
                            toolExecuted: !!scanResult,
                            scanData: scanResult,
                            logs: scanLogs
                        });
                    }
                } catch (groqErr) {
                    console.error('Groq API query error:', groqErr.response?.data || groqErr.message);
                }
            }
        }

        // 4. Sandbox Fallback AI Agent
        const fallbackReply = generateFallbackReply(message, scanResult, targetToScan, selectedModel);
        return res.json({
            reply: fallbackReply,
            modelUsed: selectedModel === 'gemini' ? 'Google Gemini Pro (Sandbox Fallback)' : 'Groq Llama 3 (Sandbox Fallback)',
            toolExecuted: !!scanResult,
            scanData: scanResult,
            logs: scanLogs
        });

    } catch (error) {
        console.error('Chat endpoint error:', error);
        res.status(500).json({ message: 'Server error during chat advisory generation' });
    }
};

// Generates high-fidelity cybersecurity expert responses locally
function generateFallbackReply(message, scanResult, targetToScan, modelName) {
    const header = `⚠️ **Notice**: Running in Sandbox Mode (no API key configured for ${modelName === 'gemini' ? 'Gemini' : 'Groq'} in \`backend/.env\`). Showing local threat intelligence simulation.\n\n`;
    
    if (scanResult) {
        return `${header}### 🛡️ AI Security Advisory: Domain Threat Assessment
We ran an automated security scan on the extracted target: **${targetToScan}**.

**Analysis Summary:**
- **Calculated Risk Severity**: \`${scanResult.risk_score}/100\`
- **Platform Verdict**: **${scanResult.prediction.toUpperCase()}**

#### 🔍 Heuristic Vector Details:
${scanResult.explanations.map(exp => `- **Threat Marker**: ${exp}`).join('\n')}

#### 💡 Safety Recommendation:
${scanResult.risk_score >= 50 
    ? `🔴 **Danger Zone**: This domain carries high-risk characteristics. We recommend blocking connections immediately. Do **not** input credentials, credit cards, or user tokens on this host.`
    : `🟢 **Secure Warning**: The domain resolved cleanly and has no active phishing heuristics, but always verify TLS details and headers before authenticating.`}`;
    }

    const msgLower = message.toLowerCase();
    
    if (msgLower.includes('harvest') || msgLower.includes('credential')) {
        return `${header}### 🔑 Understanding Credential Harvesting
Credential harvesting is a primary phishing vector where attackers set up replica landing pages of common services (like Microsoft, Google, or banking portals) to deceive users into keying in credentials.

**Core Identifiers:**
1. **Misspelled/Typosquat Hostnames**: e.g., \`micros0ft-support.com\` instead of \`microsoft.com\`.
2. **Recent Domain Ages**: Attackers setup domains hours or days prior to dispatching phishing emails.
3. **No SSL or Free/Automated SSL certificates** lacking commercial validation histories.

**Defense Checklist:**
- Enforce hardware Security Keys (FIDO2) or Time-based OTP (TOTP).
- Deploy active DNS filtration firewalls that scan domains for reputation markers.`;
    }

    if (msgLower.includes('header') || msgLower.includes('email')) {
        return `${header}### 📧 Inspecting Email Headers for Phishing
Malicious messages frequently employ sender spoofing. Analyzing raw headers helps verify source integrity.

**Key Fields to Audit:**
- **\`Authentication-Results\`**: Check checkmarks for **SPF** (Sender Policy Framework), **DKIM** (DomainKeys Identified Mail), and **DMARC**.
- **\`Return-Path\`**: Verify if the bounce-back address aligns with the visible sender address in the \`From\` header.
- **\`Received\`**: Inspect the server transit IP hops. Check if the initial sending mail-transfer agent matches expected SPF limits.`;
    }

    return `${header}### 🤖 TruPhish Threat Advisor Console
Welcome to the AI Security Advisory Bot. I can assist you in inspecting phishing patterns, diagnosing threat vectors, or parsing specific domains.

**Common Scenarios to Ask:**
- "How do I recognize credential harvesting?"
- "What security metrics should I look for in email headers?"
- "Check domain: \`paypal-secure-billing-login.xyz\`" *(Make sure to enable **Agentic Deep Sweep** to scan automatically!)*`;
}
