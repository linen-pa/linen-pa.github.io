import { onRequest } from 'firebase-functions/v2/https';
import { readFileSync } from 'fs';
import { join } from 'path';

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
