# Linen Cloud Functions

This directory contains Firebase Cloud Functions that securely handle API calls to Google's Gemini API.

## Security Architecture

- **API Key Storage**: The Gemini API key is stored in Firebase Secret Manager, never exposed to the frontend
- **Backend Proxy**: All Gemini API calls go through these Cloud Functions, not directly from the browser
- **Frontend Security**: The frontend only calls these functions via Firebase's callable interface

## Setup

### Prerequisites
- Firebase CLI installed (`npm install -g firebase-tools`)
- Firebase project initialized in this repo

### Deploy Cloud Functions

```bash
# Install dependencies
cd functions
npm install

# Deploy to Firebase
cd ..
firebase deploy --only functions
```

### Set the Gemini API Key

Once deployed, set your Gemini API key in Firebase:

```bash
firebase functions:config:set gemini.api_key="YOUR_ACTUAL_KEY_HERE"
firebase deploy --only functions
```

Or use the Firebase Console to set the secret:

1. Go to Firebase Console > Project Settings > Functions
2. Create a new secret: `GEMINI_API_KEY`
3. Set the value to your actual Gemini API key
4. Redeploy functions to access the secret

## Functions

### `callGeminiAPI`

Securely calls the Gemini API on behalf of the frontend.

**Request:**
```json
{
  "messages": [
    { "role": "user", "parts": [{ "text": "Hello" }] }
  ],
  "model": "gemini-2.5-flash"
}
```

**Response:**
```json
{
  "success": true,
  "data": { ... }
}
```

### `testConnection`

Health check endpoint to verify the backend is ready.

## Local Testing

To test locally:

```bash
firebase emulators:start
```

Then call the functions from the frontend using the emulator URLs.
