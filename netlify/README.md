# SSH Secure Messaging - Netlify Deployment

## Deploy to Netlify

### Option 1: Drag & Drop (Fastest)
1. Go to [https://app.netlify.com/drop](https://app.netlify.com/drop)
2. Drag the `netlify` folder and drop it on the page
3. Your site will be live in seconds!

### Option 2: Deploy via GitHub
1. Push this `netlify` folder to a GitHub repository
2. Go to [https://app.netlify.com](https://app.netlify.com)
3. Click "Add new site" → "Import an existing project"
4. Connect your GitHub repo
5. Set the "Publish directory" to `netlify`
6. Click "Deploy site"

### Option 3: Netlify CLI
```bash
# Install Netlify CLI
npm install -g netlify-cli

# Login to Netlify
netlify login

# Deploy from the netlify folder
cd netlify
netlify deploy --prod
```

---

## Features
- 🔒 **RSA-2048** encryption
- 🔐 **AES-256-GCM** symmetric encryption
- 🔑 **MD5** integrity verification
- 📋 One-click copy encrypted messages
- ⚡ Auto-decrypt on paste
- 📱 Mobile responsive design

## Note
This is a client-side only version. Messages encrypted on one browser session can only be decrypted in the same session (keys are generated fresh each time).
