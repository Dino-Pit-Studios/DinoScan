# Quick Fix: JFrog Frogbot Configuration Error

**Error Message:**
```
Error: 6 [Error] JF_USER and JF_PASSWORD or JF_ACCESS_TOKEN environment variables are missing
```

## 🚀 Quick Solution (2 minutes)

### What you need:
1. A JFrog Platform URL
2. An access token OR username+password

### Where to put it:
Add these as GitHub Secrets at:
**https://github.com/Dino-Pit-Studios/DinoScan/settings/secrets/actions**

### Required Secrets:

**Required:**
- `JF_URL` = Your JFrog URL (e.g., `https://yourcompany.jfrog.io`)

**Pick ONE authentication method:**

**Option A (Recommended):**
- `JF_ACCESS_TOKEN` = Your JFrog access token

**Option B (Alternative):**
- `JF_USER` = Your JFrog username
- `JF_PASSWORD` = Your JFrog password

---

## 📖 Detailed Guide

For complete step-by-step instructions, see: **[JFROG_SETUP.md](../JFROG_SETUP.md)**

## ❓ Don't have JFrog credentials?

You can either:
1. Sign up for free: https://jfrog.com/start-free/
2. Disable the workflow (see [JFROG_SETUP.md](../JFROG_SETUP.md#-disabling-frogbot-optional))
