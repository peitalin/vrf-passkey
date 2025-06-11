# NPM Publishing Guide

This guide covers the complete process for packaging and publishing the @near/passkey-sdk to NPM.

## 📋 Pre-Publishing Checklist

### 1. **Version Management**
```bash
# Update version in package.json (choose one)
npm version patch    # 0.1.0 -> 0.1.1 (bug fixes)
npm version minor    # 0.1.0 -> 0.2.0 (new features)
npm version major    # 0.1.0 -> 1.0.0 (breaking changes)

# Or manually edit package.json version field
```

### 2. **Quality Checks**
```bash
# Run linting
npm run lint

# Run tests
npm test

# Type checking
npm run type-check

# Build the package
npm run build
```

### 3. **Documentation Updates**
- [ ] Update CHANGELOG.md with new features/fixes
- [ ] Update README.md if API changed
- [ ] Verify examples still work
- [ ] Update version in documentation

## 🛠️ Building the Package

### Complete Build Process
```bash
# Clean previous builds
npm run build:clean

# Build TypeScript declarations
npm run build:ts

# Bundle with Rollup (ESM + CJS)
npm run build:bundle

# Or run complete build
npm run build
```

### Verify Build Output
```bash
# Check dist/ structure
ls -la dist/
# Should show:
# - dist/esm/     (ES modules)
# - dist/cjs/     (CommonJS)
# - dist/types/   (TypeScript declarations)

# Test bundle sizes
du -sh dist/*
```

## 📦 Package Validation

### 1. **Test Package Locally**
```bash
# Pack the package (creates .tgz file)
npm pack

# Install locally in test project
cd /path/to/test-project
npm install /path/to/@near-passkey-sdk-0.1.0.tgz

# Test imports
node -e "console.log(require('@near/passkey-sdk'))"
```

### 2. **Dry Run Publishing**
```bash
# See what would be published
npm publish --dry-run

# Check published files
npm pack --dry-run
```

### 3. **Package Size Check**
```bash
# Check package size
npm pack && tar -tzf near-passkey-sdk-*.tgz | head -20
```

## 🚀 Publishing to NPM

### 1. **NPM Account Setup**
```bash
# Login to NPM (one-time setup)
npm login

# Verify login
npm whoami

# Check access to @near scope
npm access list packages @near
```

### 2. **Publish Commands**

#### **Initial Publish (Public)**
```bash
# For scoped packages, must specify public access
npm publish --access public

# Or with tag for pre-release
npm publish --tag beta --access public
```

#### **Subsequent Releases**
```bash
# Regular release
npm publish

# Pre-release with tag
npm publish --tag beta
npm publish --tag alpha
npm publish --tag next
```

### 3. **Post-Publish Verification**
```bash
# Check package on NPM
npm info @near/passkey-sdk

# Install from NPM
npm install @near/passkey-sdk

# Check in browser
open https://www.npmjs.com/package/@near/passkey-sdk
```

## 🔄 Automated Publishing with GitHub Actions

### GitHub Workflow Example
Create `.github/workflows/publish.yml`:

```yaml
name: Publish NPM Package

on:
  push:
    tags:
      - 'v*'

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '18'
          registry-url: 'https://registry.npmjs.org'

      - name: Install dependencies
        run: npm ci

      - name: Run tests
        run: npm test

      - name: Build package
        run: npm run build

      - name: Publish to NPM
        run: npm publish --access public
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
```

### Setup Required Secrets
1. Go to GitHub repo → Settings → Secrets
2. Add `NPM_TOKEN` with your NPM access token

### Create NPM Access Token
```bash
# Generate token at: https://www.npmjs.com/settings/tokens
# Or via CLI:
npm token create --read-only  # for CI/CD reading
npm token create              # for publishing
```

## 📊 Release Workflow

### 1. **Semantic Versioning**
- **Patch** (0.1.0 → 0.1.1): Bug fixes, no API changes
- **Minor** (0.1.0 → 0.2.0): New features, backward compatible
- **Major** (0.1.0 → 1.0.0): Breaking changes

### 2. **Release Process**
```bash
# 1. Create release branch
git checkout -b release/v0.2.0

# 2. Update version and changelog
npm version minor
# Updates package.json and creates git tag

# 3. Update CHANGELOG.md
# Add new section for v0.2.0

# 4. Commit changes
git add .
git commit -m "chore: prepare release v0.2.0"

# 5. Push and create PR
git push origin release/v0.2.0

# 6. After PR merge, tag and publish
git tag v0.2.0
git push origin v0.2.0

# 7. Publish (manual or automated)
npm publish --access public
```

## 🔍 Troubleshooting

### Common Issues

#### **Permission Denied**
```bash
# Check NPM login
npm whoami

# Re-login if needed
npm logout
npm login
```

#### **Package Already Exists**
```bash
# Check if version already published
npm info @near/passkey-sdk versions --json

# Increment version
npm version patch
```

#### **Build Errors**
```bash
# Clear node_modules and reinstall
rm -rf node_modules package-lock.json
npm install

# Clear TypeScript cache
rm -rf dist/ *.tsbuildinfo
npm run build
```

#### **Large Package Size**
```bash
# Check what's being included
npm pack --dry-run

# Add to .npmignore:
echo "src/" >> .npmignore
echo "tests/" >> .npmignore
echo "*.test.ts" >> .npmignore
```

## 📈 Post-Publishing

### 1. **Verify Installation**
```bash
# Test in clean environment
npx create-react-app test-app
cd test-app
npm install @near/passkey-sdk
```

### 2. **Update Documentation**
- Update GitHub README
- Update examples repository
- Announce on social media/Discord

### 3. **Monitor Usage**
```bash
# Check download stats
npm info @near/passkey-sdk

# Monitor for issues
# - GitHub issues
# - NPM feedback
# - Community reports
```

## 🏷️ Tag Management

### List Tags
```bash
# Show published tags
npm info @near/passkey-sdk dist-tags

# Show all versions
npm info @near/passkey-sdk versions
```

### Tag Commands
```bash
# Add tag to existing version
npm dist-tag add @near/passkey-sdk@0.1.1 stable

# Remove tag
npm dist-tag rm @near/passkey-sdk beta

# Latest tag is default
npm dist-tag add @near/passkey-sdk@0.2.0 latest
```

This guide provides everything needed to successfully package and publish the passkey SDK to NPM!