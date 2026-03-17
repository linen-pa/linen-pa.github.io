import { onCall, HttpsError } from 'firebase-functions/v2/https';
import { defineSecret } from 'firebase-functions/params';

// Define the Gemini API key as a secret
const geminiApiKey = defineSecret('GEMINI_API_KEY');

/**
 * Cloud Function: callGeminiAPI
 * Securely calls the Gemini API on behalf of the frontend
 * API key is stored in Firebase Secret Manager, never exposed to client
 */
export const callGeminiAPI = onCall({ secrets: [geminiApiKey] }, async (request) => {
    try {
        const { messages, model = 'gemini-2.5-flash' } = request.data;

        // Validate input
        if (!messages || !Array.isArray(messages)) {
            throw new HttpsError(
                'invalid-argument',
                'Missing or invalid messages array'
            );
        }

        if (messages.length === 0) {
            throw new HttpsError(
                'invalid-argument',
                'Messages array cannot be empty'
            );
        }

        // Call Gemini API with secure key
        const response = await fetch(
            `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${geminiApiKey.value()}`,
            {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    contents: messages,
                    generationConfig: {
                        temperature: 1,
                        topK: 40,
                        topP: 0.95,
                        maxOutputTokens: 8192,
                    },
                }),
            }
        );

        if (!response.ok) {
            const error = await response.json();
            console.error('Gemini API error:', error);
            throw new HttpsError(
                'internal',
                `Gemini API error: ${error.error?.message || 'Unknown error'}`
            );
        }

        const data = await response.json();
        return {
            success: true,
            data: data,
        };
    } catch (error) {
        console.error('callGeminiAPI error:', error);
        throw new HttpsError(
            'internal',
            error.message || 'Failed to call Gemini API'
        );
    }
});

/**
 * Cloud Function: testConnection
 * Simple health check to verify the Cloud Function is working
 */
export const testConnection = onCall(async (request) => {
    try {
        return {
            success: true,
            message: 'Linen backend is ready',
            timestamp: new Date().toISOString(),
        };
    } catch (error) {
        throw new HttpsError('internal', 'Backend connection failed');
    }
});
