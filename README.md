# ScamLens 🔍

### AI-Powered Scam Investigation

**Evidence first, safer decisions.**

ScamLens helps users investigate suspicious SMS messages, emails, and URLs using AI-powered explanations and deterministic Model Context Protocol (MCP) tools. It identifies potential warning signs, explains the evidence, highlights unknowns, and recommends safer next steps.

## 🚀 Live Demo

Try ScamLens: https://scamlens-ochre.vercel.app/

## ✨ Features

- **AI Investigation:** Generates structured reports explaining suspicious claims, potential risks, and recommended actions using Google Gemini.
- **MCP-Powered Detection:** Uses dedicated tools to extract indicators, assess messages, and inspect URL structure.
- **EvidenceTrail:** Separates observed facts, heuristic warning signs, and unknowns for transparent investigations.
- **Safe URL Inspection:** Examines URL structure without opening the destination or querying external reputation services.
- **Context-Aware Guidance:** Provides practical safety recommendations based on the submitted message and available findings.
- **Transparent Assessments:** Avoids treating heuristic results as definitive proof of fraud or safety.

## 🛠️ Tech Stack

- **Frontend:** Next.js, React, TypeScript, Tailwind CSS
- **AI:** Google Gemini API
- **Tool Integration:** Model Context Protocol (MCP) TypeScript SDK
- **Backend:** Node.js, Express
- **Validation:** Zod

## 🔧 Getting Started

### Prerequisites

- Node.js and npm
- A Google Gemini API key

### 1. Clone the repository and install dependencies

```bash
git clone <repository-url>
cd scamlens
npm install
```

### 2. Configure environment variables

Create a `.env.local` file in the project root:

```env
GEMINI_API_KEY=your_gemini_api_key
```

Keep your API key private. Never commit `.env.local` or expose secrets in client-side code.

### 3. Start the MCP server

In the first terminal:

```bash
npx tsx mcp-server/server.ts
```

The local MCP endpoint runs at `http://127.0.0.1:3001/mcp` by default.

### 4. Start the web application

In a second terminal:

```bash
npm run dev
```

Open `http://localhost:3000` in your browser.

## 🔌 MCP Tools

| Tool                 | Description                                                     |
| -------------------- | --------------------------------------------------------------- |
| `extract_indicators` | Extracts URLs, phone numbers, and potential scam warning signs. |
| `check_message`      | Assesses message warning signs using deterministic heuristics.  |
| `check_url_safely`   | Inspects URL structure without visiting the destination.        |

To test the MCP integration, keep the MCP server running and execute:

```bash
npx tsx mcp-client/test-client.ts
```

## 🛡️ Safety and Limitations

ScamLens is an advisory tool, not a guarantee that a message or URL is fraudulent or safe.

- Heuristic detection may miss threats or flag legitimate messages.
- URL structure inspection does not establish a destination's reputation.
- External URL reputation checks are not currently performed.
- AI-generated explanations may be incomplete or incorrect.

Always verify important claims independently through official websites, applications, or trusted contact channels. Never share passwords, PINs, or OTPs with suspicious sources.

## 🚀 Future Improvements

- Integration with external URL reputation services.
- Broader multilingual scam detection.
- Expanded testing for false positives and false negatives.
- Improved evidence provenance and detection accuracy.

---

**ScamLens — Investigate suspicious messages. Understand the evidence. Act safely.**
