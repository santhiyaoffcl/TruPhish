const ScanHistory = require('../models/scanHistory');
const { PhishingAgent } = require('../services/phishingAgent');

exports.scanUrl = async (req, res) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ message: 'URL is required' });

    await processScan(req.user.id, url, 'url', res);
};

exports.scanText = async (req, res) => {
    const { text } = req.body;
    if (!text) return res.status(400).json({ message: 'Text is required' });

    await processScan(req.user.id, text, 'text', res);
};

async function processScan(userId, input, type, res) {
    const startTime = Date.now();
    let scanResult = {
        risk_score: 0,
        prediction: 'unknown',
        explanations: [],
        status: 'failed'
    };

    try {
        const agent = new PhishingAgent();
        const data = type === 'url' ? await agent.scanUrl(input) : await agent.scanText(input);

        if (data) {
            scanResult.risk_score = data.risk_score;
            scanResult.prediction = data.prediction;
            scanResult.explanations = data.explanations || [];
            scanResult.status = 'success';
        }
    } catch (error) {
        console.error('Scan engine error:', error.message);
    }

    const latency_ms = Date.now() - startTime;

    try {
        const scan = new ScanHistory({
            user_id: userId,
            input,
            type,
            risk_score: scanResult.risk_score,
            prediction: scanResult.prediction,
            explanations: scanResult.explanations,
            source: 'web',
            status: scanResult.status,
            latency_ms
        });

        const savedScan = await scan.save();

        res.json({
            id: savedScan.id,
            input,
            type,
            risk_score: scanResult.risk_score,
            prediction: scanResult.prediction,
            explanations: scanResult.explanations,
            status: scanResult.status,
            latency_ms
        });
    } catch (dbError) {
        console.error('Database Error:', dbError);
        res.status(500).json({ message: 'Error saving scan history' });
    }
}

exports.getHistory = async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const offset = (page - 1) * limit;
        const search = req.query.search || '';

        const filter = {
            user_id: req.user.id,
            input: { $regex: search, $options: 'i' }
        };

        const history = await ScanHistory.find(filter)
            .sort({ created_at: -1 })
            .skip(offset)
            .limit(limit);

        const total = await ScanHistory.countDocuments(filter);

        const formattedHistory = history.map(item => ({
            id: item.id,
            input: item.input,
            type: item.type,
            risk_score: item.risk_score,
            prediction: item.prediction,
            explanations: item.explanations || [],
            source: item.source,
            status: item.status,
            latency_ms: item.latency_ms,
            created_at: item.created_at
        }));

        res.json({
            data: formattedHistory,
            pagination: {
                total,
                page,
                limit,
                totalPages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        console.error('Get history error:', error);
        res.status(500).json({ message: 'Server error retrieving history' });
    }
};

exports.clearHistory = async (req, res) => {
    try {
        const userId = req.user.id;
        await ScanHistory.deleteMany({ user_id: userId });
        res.json({ message: 'Scan history successfully cleared', success: true });
    } catch (error) {
        console.error('Clear history error:', error);
        res.status(500).json({ message: 'Server error clearing history' });
    }
};

async function processStream(req, res, input, type) {
    const startTime = Date.now();
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    if (typeof res.flushHeaders === 'function') {
        res.flushHeaders();
    }

    try {
        const agent = new PhishingAgent();
        const stream = type === 'url'
            ? agent.scanUrlStream(input, { delayed: true })
            : agent.scanTextStream(input, { delayed: true });

        let finalResult = null;
        for await (const event of stream) {
            res.write(`data: ${JSON.stringify(event)}\n\n`);
            if (event.step === 'complete') {
                finalResult = event.data;
            }
        }

        if (finalResult) {
            const latency_ms = Date.now() - startTime;
            const scan = new ScanHistory({
                user_id: req.user.id,
                input,
                type,
                risk_score: finalResult.risk_score,
                prediction: finalResult.prediction,
                explanations: finalResult.explanations || [],
                source: 'web',
                status: 'success',
                latency_ms
            });
            await scan.save();
        }
    } catch (error) {
        console.error('Scan streaming error:', error.message);
        res.write(`data: ${JSON.stringify({
            step: 'complete',
            status: 'danger',
            message: 'Failed to complete agent thread stream.',
            data: {
                risk_score: 50,
                prediction: 'unknown',
                explanations: ['Scan engine error.'],
                report: 'Analysis interrupted.',
                logs: []
            }
        })}\n\n`);
    } finally {
        res.end();
    }
}

exports.streamUrl = async (req, res) => {
    const { url } = req.query;
    if (!url) return res.status(400).json({ message: 'URL is required' });
    await processStream(req, res, url, 'url');
};

exports.streamText = async (req, res) => {
    const { text } = req.query;
    if (!text) return res.status(400).json({ message: 'Text is required' });
    await processStream(req, res, text, 'text');
};
