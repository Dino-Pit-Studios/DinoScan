# JFrog Frogbot Configuration Guide

This guide provides step-by-step instructions for configuring JFrog Frogbot in the DinoScan repository to resolve the error:
```
Error: 6 [Error] JF_USER and JF_PASSWORD or JF_ACCESS_TOKEN environment variables are missing
```

## 📋 What You Need

The Frogbot workflow (`.github/workflows/frogbot-scan-and-fix.yml`) requires JFrog credentials to scan your project for vulnerabilities using JFrog Xray. You need **one** of the following authentication methods:

### Option 1: Access Token (Recommended)
- **JF_URL**: Your JFrog platform URL
- **JF_ACCESS_TOKEN**: JFrog access token with 'read' permissions on Xray service

### Option 2: Username/Password
- **JF_URL**: Your JFrog platform URL
- **JF_USER**: JFrog username with 'read' permissions for Xray
- **JF_PASSWORD**: JFrog password

## 🔧 Step-by-Step Configuration

### Step 1: Obtain JFrog Credentials

#### If you have a JFrog Platform account:

1. **Get your JFrog URL**:
   - Log in to your JFrog Platform
   - Your URL is typically in the format: `https://yourcompany.jfrog.io`

2. **Generate an Access Token** (Recommended):
   - Navigate to: Administration → User Management → Access Tokens
   - Click "Generate Token"
   - Set the following:
     - **User**: Your username
     - **Scope**: Select "Xray" with "Read" permissions
     - **Expiration**: Set appropriate expiration date
   - Click "Generate" and copy the token (you won't see it again!)

3. **Alternative - Use Username/Password**:
   - Use your JFrog platform username
   - Use your JFrog platform password

#### If you don't have a JFrog Platform account:

You have two options:

1. **Create a free JFrog account**:
   - Visit: https://jfrog.com/start-free/
   - Sign up for a free trial
   - Follow the steps above to get your credentials

2. **Disable the Frogbot workflow**:
   - If you don't need JFrog Xray scanning, you can disable this workflow
   - See the "Disabling Frogbot" section below

### Step 2: Configure GitHub Secrets

GitHub Secrets allow you to securely store credentials without exposing them in your code.

1. **Navigate to your repository secrets**:
   - Go to: https://github.com/Dino-Pit-Studios/DinoScan/settings/secrets/actions
   - Or manually navigate: Repository → Settings → Secrets and variables → Actions

2. **Add the required secrets**:

   Click "New repository secret" and add each of the following:

   **Required for both authentication methods:**
   - **Name**: `JF_URL`
   - **Value**: Your JFrog platform URL (e.g., `https://yourcompany.jfrog.io`)

   **For Access Token authentication (Option 1 - Recommended):**
   - **Name**: `JF_ACCESS_TOKEN`
   - **Value**: Your JFrog access token (the long string you copied earlier)

   **For Username/Password authentication (Option 2 - Alternative):**
   - **Name**: `JF_USER`
   - **Value**: Your JFrog username
   - **Name**: `JF_PASSWORD`
   - **Value**: Your JFrog password

3. **Verify secrets are added**:
   - You should see the secret names listed (values are hidden for security)
   - The workflow will automatically use these secrets

### Step 3: Update Workflow Configuration (if using Username/Password)

If you're using Username/Password authentication instead of Access Token:

1. Edit `.github/workflows/frogbot-scan-and-fix.yml`
2. Uncomment lines 45-46 and 48-49:
   ```yaml
   # Change from:
   # JF_USER: ${{ secrets.JF_USER }}
   # To:
   JF_USER: ${{ secrets.JF_USER }}
   
   # Change from:
   # JF_PASSWORD: ${{ secrets.JF_PASSWORD }}
   # To:
   JF_PASSWORD: ${{ secrets.JF_PASSWORD }}
   ```
3. Comment out line 41 (or leave it if you want to use both methods):
   ```yaml
   # JF_ACCESS_TOKEN: ${{ secrets.JF_ACCESS_TOKEN }}
   ```

### Step 4: Test the Configuration

1. **Trigger the workflow**:
   - Push a commit to the `main` branch
   - Or manually trigger the workflow from the Actions tab

2. **Verify it works**:
   - Go to: https://github.com/Dino-Pit-Studios/DinoScan/actions
   - Check the "Frogbot Scan and Fix" workflow run
   - It should complete without the authentication error

## 🚫 Disabling Frogbot (Optional)

If you don't want to use JFrog Frogbot scanning, you can disable the workflow:

### Option 1: Delete the workflow file
```bash
rm .github/workflows/frogbot-scan-and-fix.yml
git commit -m "Remove JFrog Frogbot workflow"
git push
```

### Option 2: Rename the file to disable it
```bash
mv .github/workflows/frogbot-scan-and-fix.yml .github/workflows/frogbot-scan-and-fix.yml.disabled
git commit -m "Disable JFrog Frogbot workflow"
git push
```

### Option 3: Add a workflow condition to skip it
Edit `.github/workflows/frogbot-scan-and-fix.yml` and add a condition:
```yaml
on:
  push:
    branches: [ "main" ]
  # Disable workflow by adding impossible condition
  workflow_dispatch:
    
jobs:
  create-fix-pull-requests:
    # Add this line to disable the workflow
    if: false
    runs-on: ubuntu-latest
```

## 🔍 Troubleshooting

### Error: "JF_USER and JF_PASSWORD or JF_ACCESS_TOKEN environment variables are missing"

**Cause**: GitHub secrets are not configured or named incorrectly.

**Solution**:
1. Verify secrets exist at: https://github.com/Dino-Pit-Studios/DinoScan/settings/secrets/actions
2. Check that secret names match exactly (case-sensitive):
   - `JF_URL` (not `JF_Url` or `jf_url`)
   - `JF_ACCESS_TOKEN` (not `JF_TOKEN` or `JFROG_ACCESS_TOKEN`)
   - `JF_USER` (not `JFROG_USER`)
   - `JF_PASSWORD` (not `JFROG_PASSWORD`)

### Error: "JF_URL is not a valid URL"

**Cause**: The JF_URL secret is empty or malformed.

**Solution**:
1. Ensure JF_URL includes the protocol: `https://yourcompany.jfrog.io`
2. Don't include trailing slashes or paths

### Error: "401 Unauthorized" or "403 Forbidden"

**Cause**: Invalid credentials or insufficient permissions.

**Solution**:
1. Verify your access token hasn't expired
2. Ensure the token/user has "read" permissions for Xray
3. Try generating a new access token
4. Verify you can log in to JFrog Platform with these credentials

### Workflow doesn't trigger

**Cause**: Workflow only triggers on push to `main` branch.

**Solution**:
1. Ensure you're pushing to the `main` branch
2. Or manually trigger from Actions tab: https://github.com/Dino-Pit-Studios/DinoScan/actions/workflows/frogbot-scan-and-fix.yml

## 📚 Additional Resources

- [Frogbot Documentation](https://docs.jfrog-applications.jfrog.io/jfrog-applications/frogbot)
- [JFrog Platform Access Tokens](https://jfrog.com/help/r/jfrog-platform-administration-documentation/access-tokens)
- [GitHub Encrypted Secrets](https://docs.github.com/en/actions/security-guides/encrypted-secrets)
- [Frogbot Configuration File](https://docs.jfrog-applications.jfrog.io/jfrog-applications/frogbot/setup-frogbot/frogbot-configuration)

## ✅ Quick Checklist

Before the workflow can run successfully, ensure:

- [ ] You have a JFrog Platform account
- [ ] You've generated a JFrog access token (or have username/password)
- [ ] You've added `JF_URL` secret to GitHub
- [ ] You've added either `JF_ACCESS_TOKEN` or both `JF_USER` and `JF_PASSWORD` secrets
- [ ] Secret names match exactly (case-sensitive)
- [ ] Your JFrog credentials have Xray read permissions
- [ ] You've pushed a commit to `main` branch to trigger the workflow

## 💡 Pro Tips

1. **Use Access Tokens**: They're more secure than username/password and can be easily rotated
2. **Set expiration dates**: For access tokens to enhance security
3. **Use least privilege**: Only grant "read" permissions to Xray, not admin access
4. **Document your setup**: Keep track of when tokens were created and their expiration dates
5. **Monitor workflow runs**: Check the Actions tab regularly to ensure scans are working

---

**Need more help?** 
- Check existing issues: https://github.com/Dino-Pit-Studios/DinoScan/issues
- Create a new issue: https://github.com/Dino-Pit-Studios/DinoScan/issues/new
- Review Frogbot documentation: https://docs.jfrog-applications.jfrog.io/jfrog-applications/frogbot
