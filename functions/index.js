import { onRequest } from 'firebase-functions/v2/https';
import { readFileSync } from 'fs';
import { join } from 'path';
import { initializeApp, getApps } from 'firebase-admin/app';
import { getDatabase } from 'firebase-admin/database';

// Initialize Firebase Admin SDK (uses Application Default Credentials in Cloud Run)
if (!getApps().length) {
    initializeApp({ databaseURL: 'https://linen-a1142-default-rtdb.firebaseio.com' });
}

// Load environment variables from .env.local for local development
let envVars = {};
try {
    const envPath = join(import.meta.url.replace('file://', ''), '..', '.env.local');
    const envContent = readFileSync(envPath, 'utf-8');
    envContent.split('\n').forEach(line => {
        const [key, value] = line.split('=');
        if (key && value) {
            envVars[key.trim()] = value.trim();
        }
    });
} catch (e) {
    // .env.local not found - will use process.env instead
}

// CORS headers for all responses
const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

// PayPal plan ID → tier name mapping
const PLAN_TIERS = {
    'P-8JA60924BR1205352NG5TBHA': 'pro',
    'P-5SU13892KA649720WNG5TC3I': 'popular',
    'P-7X1016697X939624PNG5TESY': 'ultimate',
};

// Daily token allowance per tier
const TIER_DAILY_TOKENS = {
    pro:      200,
    popular:  600,
    ultimate: 1500,
};

/**
 * Cloud Function: callGeminiAPI
 * Securely calls the Gemini API on behalf of the frontend
 * API key is stored in environment variables, never exposed to client
 */
export const callGeminiAPI = onRequest(async (req, res) => {
    // Handle CORS preflight
    if (req.method === 'OPTIONS') {
        res.set(corsHeaders);
        res.status(204).send('');
        return;
    }

    res.set(corsHeaders);

    try {
        const { contents, systemInstruction, generationConfig, model = 'gemini-2.5-flash' } = req.body;

        // Validate input
        if (!contents || !Array.isArray(contents)) {
            return res.status(400).json({
                error: 'Missing or invalid contents array',
            });
        }

        if (contents.length === 0) {
            return res.status(400).json({
                error: 'Contents array cannot be empty',
            });
        }

        // Get API key from environment
        // Try: process.env (from Firebase config), then envVars (from .env.local for local dev)
        const apiKey = process.env.GEMINI_API_KEY || envVars.GEMINI_API_KEY;
        if (!apiKey) {
            console.error('GEMINI_API_KEY not configured. Available env vars:', Object.keys(process.env).filter(k => k.includes('GEMINI')));
            return res.status(500).json({
                error: 'API key not configured on backend',
            });
        }

        // Build request body with systemInstruction
        const requestPayload = {
            contents,
            generationConfig: generationConfig || {
                temperature: 1,
                topK: 40,
                topP: 0.95,
                maxOutputTokens: 8192,
            },
        };

        // Add system instruction if provided
        if (systemInstruction) {
            requestPayload.systemInstruction = systemInstruction;
        }

        // Call Gemini API with secure key
        const response = await fetch(
            `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`,
            {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(requestPayload),
            }
        );

        if (!response.ok) {
            const error = await response.json();
            console.error('Gemini API error:', error);
            return res.status(500).json({
                error: `Gemini API error: ${error.error?.message || 'Unknown error'}`,
            });
        }

        const data = await response.json();
        return res.json({
            success: true,
            data: data,
        });
    } catch (error) {
        console.error('callGeminiAPI error:', error);
        return res.status(500).json({
            error: error.message || 'Failed to call Gemini API',
        });
    }
});

/**
 * Cloud Function: generateImage
 * Generates images using Gemini's image generation capability
 */
export const generateImage = onRequest(async (req, res) => {
    // Handle CORS preflight
    if (req.method === 'OPTIONS') {
        res.set(corsHeaders);
        res.status(204).send('');
        return;
    }

    res.set(corsHeaders);

    try {
        const { prompt } = req.body;

        // Validate input
        if (!prompt || typeof prompt !== 'string') {
            return res.status(400).json({
                error: 'Missing or invalid prompt',
            });
        }

        // Get API key from environment
        const apiKey = process.env.GEMINI_API_KEY || envVars.GEMINI_API_KEY;
        if (!apiKey) {
            console.error('GEMINI_API_KEY not configured');
            return res.status(500).json({
                error: 'API key not configured on backend',
            });
        }

        // Call gemini-2.5-flash-image — the correct model for image generation
        const response = await fetch(
            `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-image:generateContent?key=${apiKey}`,
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    contents: [{ role: 'user', parts: [{ text: prompt }] }],
                    generationConfig: { responseModalities: ['IMAGE', 'TEXT'] },
                }),
            }
        );

        if (!response.ok) {
            const errBody = await response.json().catch(() => ({}));
            console.error('Image generation failed:', errBody);
            return res.status(500).json({
                error: `Image generation failed: ${errBody.error?.message || 'Unknown error'}`,
            });
        }

        const data = await response.json();
        const parts = data.candidates?.[0]?.content?.parts || [];
        const imagePart = parts.find(p => p.inlineData?.mimeType?.startsWith('image/'));

        if (!imagePart) {
            return res.status(500).json({ error: 'No image in response' });
        }

        return res.json({
            success: true,
            imageData: imagePart.inlineData.data,
            mimeType: imagePart.inlineData.mimeType,
        });
    } catch (error) {
        console.error('generateImage error:', error);
        return res.status(500).json({
            error: error.message || 'Failed to generate image',
        });
    }
});

/**
 * Cloud Function: testConnection
 * Simple health check to verify the Cloud Function is working
 */
export const testConnection = onRequest(async (req, res) => {
    // Handle CORS preflight
    if (req.method === 'OPTIONS') {
        res.set(corsHeaders);
        res.status(204).send('');
        return;
    }

    res.set(corsHeaders);

    try {
        return res.json({
            success: true,
            message: 'Linen backend is ready',
            timestamp: new Date().toISOString(),
        });
    } catch (error) {
        return res.status(500).json({
            error: 'Backend connection failed',
        });
    }
});

/**
 * Cloud Function: paypalWebhook
 * Receives PayPal subscription lifecycle events and updates Firebase accordingly.
 * PayPal sends: ACTIVATED, RENEWED, CANCELLED, SUSPENDED, EXPIRED events.
 * The subscription's custom_id holds the user's Firebase UID — set during createSubscription.
 */
export const paypalWebhook = onRequest(async (req, res) => {
    // Handle CORS preflight
    if (req.method === 'OPTIONS') {
        res.set(corsHeaders);
        res.status(204).send('');
        return;
    }

    res.set(corsHeaders);

    try {
        const event = req.body;
        const eventType = event.event_type;
        const resource = event.resource;

        const subscriptionId = resource?.id;
        const planId = resource?.plan_id;
        const uid = resource?.custom_id; // Firebase UID — passed during createSubscription

        // Always return 200 to PayPal immediately to acknowledge receipt.
        // PayPal retries if it gets anything other than 200.
        if (!uid) {
            console.warn(`PayPal webhook: No custom_id in payload for event ${eventType}`);
            return res.status(200).json({ received: true });
        }

        const tier = PLAN_TIERS[planId] || null;
        const db = getDatabase();
        const userRef = db.ref(`users/${uid}`);

        if (
            eventType === 'BILLING.SUBSCRIPTION.ACTIVATED' ||
            eventType === 'BILLING.SUBSCRIPTION.RENEWED' ||
            eventType === 'BILLING.SUBSCRIPTION.PAYMENT.SUCCEEDED'
        ) {
            // Grant or renew subscription access — extend expiry by ~32 days (buffer over 30)
            const expiry = Date.now() + 32 * 24 * 60 * 60 * 1000;
            await userRef.update({
                subscriptionTier:   tier,
                subscriptionId:     subscriptionId,
                subscriptionExpiry: expiry,
                subscriptionActive: true,
                tierTokenBalance:   TIER_DAILY_TOKENS[tier] || 0,
                lastTierRefill:     Date.now(),
                hasPurchased:       true,
            });
            console.log(`PayPal webhook: Subscription activated/renewed — uid=${uid}, tier=${tier}`);

        } else if (
            eventType === 'BILLING.SUBSCRIPTION.CANCELLED' ||
            eventType === 'BILLING.SUBSCRIPTION.SUSPENDED' ||
            eventType === 'BILLING.SUBSCRIPTION.EXPIRED'
        ) {
            // Revoke subscription access — keep hasPurchased true for audit trail
            await userRef.update({
                subscriptionTier:   null,
                subscriptionActive: false,
                tierTokenBalance:   0,
            });
            console.log(`PayPal webhook: Subscription ended — uid=${uid}, event=${eventType}`);
        }

        return res.status(200).json({ received: true });

    } catch (error) {
        console.error('PayPal webhook error:', error);
        // Still return 200 so PayPal doesn't retry indefinitely
        return res.status(200).json({ received: true });
    }
});
