# OpenClaw Security Analysis Summary

**Analysis Date**: February 24, 2026  
**Target**: OpenClaw AI Agent Framework  
**Analysis Tool**: AgentXploit with gpt-5.1-codex  
**Total Vulnerabilities Found**: 10

---

## Executive Summary

Comprehensive security analysis of the OpenClaw codebase revealed 10 security vulnerabilities across multiple categories including Prompt Injection, SSRF, Access Control Bypass, RCE, and Data Exfiltration. The analysis covered >10 high-risk tools with complete dataflow tracing from untrusted inputs to sensitive operations.

---

## Vulnerability Details

### 🔴 CRITICAL Severity (2-3 findings)

#### 1. **Nodes Tool - RCE via Approval Bypass**
- **Type**: Remote Code Execution (RCE) / Approval Bypass
- **Severity**: CRITICAL
- **Location**: Nodes tool API (`system.run`, `system.notify`)
- **Attack Vector**: 
  - Attacker exploits reusable approvals in the nodes tool
  - `system.run` and `system.notify` exposed via API without proper throttling
  - No action-level validation on repeated approval usage
  - Enables arbitrary command execution on the host system
- **Impact**: Full system compromise, arbitrary code execution
- **Exploitation**: 
  1. Obtain approval for a benign node action
  2. Reuse approval token for malicious `system.run` commands
  3. Execute arbitrary shell commands without re-approval

#### 2. **Gateway Tool - Authentication Bypass via Owner Spoofing**
- **Type**: Authentication Bypass / Privilege Escalation
- **Severity**: HIGH/CRITICAL
- **Location**: Gateway tool (marked "ownerOnly")
- **Attack Vector**:
  - Gateway tool restricted to "ownerOnly" but lacks runtime validation
  - Remote sessions can spoof owner status
  - No cryptographic verification of session ownership
  - Bypasses access controls on privileged gateway operations
- **Impact**: Unauthorized access to admin functions, privilege escalation
- **Exploitation**:
  1. Craft remote session with spoofed owner metadata
  2. Invoke gateway tool operations reserved for owners
  3. Gain elevated privileges without authentication

#### 3. **Browser Tool - Prompt Injection via Untrusted JavaScript**
- **Type**: Indirect Prompt Injection
- **Severity**: HIGH/CRITICAL
- **Location**: Browser snapshots, console logs, browser output processing
- **Attack Vector**:
  - Browser tool captures snapshots/console/logs from untrusted websites
  - Malicious JavaScript injected into captured content
  - Content flows directly into LLM context without sanitization
  - Enables indirect prompt injection attacks
- **Impact**: LLM manipulation, data exfiltration, workflow hijacking
- **Exploitation**:
  1. Attacker hosts webpage with malicious JS in console.log()
  2. Agent visits page using browser tool
  3. Malicious instructions embedded in console output
  4. LLM processes injected instructions as legitimate commands

---

### 🟠 HIGH Severity (5-6 findings)

#### 4. **Trusted-Network SSRF via Gemini Citations**
- **Type**: Server-Side Request Forgery (SSRF)
- **Severity**: HIGH
- **Location**: Gemini citation resolution mechanism
- **Attack Vector**:
  - Trusted-network SSRF policy allows internal host probing
  - Gemini citations resolved without strict URL validation
  - Can access cloud metadata endpoints (169.254.169.254)
  - Bypasses network segmentation controls
- **Impact**: Internal network reconnaissance, cloud metadata access, credential theft
- **Exploitation**:
  1. Inject crafted citation pointing to internal IP
  2. Gemini resolver fetches internal resource
  3. Access AWS/GCP metadata endpoints for credentials

#### 5. **Sessions Access Control Bypass**
- **Type**: Broken Access Control / Information Disclosure
- **Severity**: HIGH
- **Location**: `sessions_send`, `sessions_history` tools
- **Attack Vector**:
  - Weak visibility guard allows cross-agent data access
  - Session IDs and labels can be enumerated/guessed
  - Insufficient isolation between agent sessions
  - Label-based bypass of session boundaries
- **Impact**: Unauthorized access to other agents' conversation history and data
- **Exploitation**:
  1. Enumerate or guess session IDs/labels
  2. Use sessions_send to inject data into other sessions
  3. Use sessions_history to read sensitive conversations

#### 6. **Web_fetch SSRF via Redwood/Firecrawl Fallback**
- **Type**: Server-Side Request Forgery (SSRF)
- **Severity**: MEDIUM/HIGH
- **Location**: Web_fetch tool with Redwood/Firecrawl fallback
- **Attack Vector**:
  - Redwood fallback path still accessible via Firecrawl
  - Can target internal metadata endpoints
  - URL validation insufficient for fallback paths
  - Bypasses primary SSRF protections
- **Impact**: Internal network access, metadata endpoint exploitation
- **Exploitation**:
  1. Trigger fallback to Firecrawl mechanism
  2. Specify internal metadata URL (http://169.254.169.254/...)
  3. Retrieve cloud credentials or internal data

#### 7. **Canvas Tool - Path Traversal via LLM-Controlled jsonlPath**
- **Type**: Path Traversal / Arbitrary File Access
- **Severity**: MEDIUM/HIGH
- **Location**: Canvas tool file path handling
- **Attack Vector**:
  - `jsonlPath` parameter controlled by LLM output
  - Insufficient path restriction (only canonical check)
  - No symlink protection or sandbox enforcement
  - Can access files outside intended directory
- **Impact**: Unauthorized file system access, sensitive file disclosure
- **Exploitation**:
  1. Manipulate LLM via prompt injection to output malicious path
  2. Use path traversal sequences (../) or symlinks
  3. Access sensitive files (SSH keys, configs, credentials)

#### 8. **Browser Upload - Data Exfiltration via Unsanitized File Content**
- **Type**: Data Exfiltration / Content Injection
- **Severity**: HIGH
- **Location**: Browser file upload functionality
- **Attack Vector**:
  - Uses `resolveExistingPathsWithinRoot` for path validation
  - File contents NOT sanitized before upload
  - Can upload arbitrary sensitive files from host filesystem
  - Content flows to external browser/APIs without filtering
- **Impact**: Sensitive file exfiltration, credential theft
- **Exploitation**:
  1. Trick LLM into specifying sensitive file path (/etc/passwd, ~/.ssh/id_rsa)
  2. Browser upload resolves path successfully
  3. File contents transmitted to attacker-controlled endpoint

---

### 🟡 MEDIUM Severity (2-3 findings)

#### 9. **Cron Tool - Arbitrary Webhook Injection**
- **Type**: SSRF / Webhook Injection
- **Severity**: MEDIUM/HIGH
- **Location**: Cron tool webhook configuration
- **Attack Vector**:
  - Accepts arbitrary webhook URLs without allowlisting
  - No validation of webhook destination domains
  - Can target internal services or attacker endpoints
  - Enables automated SSRF attacks on schedule
- **Impact**: Internal service abuse, data exfiltration via webhooks
- **Exploitation**:
  1. Configure cron job with webhook to internal service
  2. Schedule periodic requests to probe/attack internal infrastructure
  3. Exfiltrate data to attacker-controlled webhook endpoint

#### 10. **Memory_search - Information Disclosure via Embedding Errors**
- **Type**: Information Disclosure / Error-Based Leakage
- **Severity**: LOW/MEDIUM
- **Location**: Memory search fallback error handling
- **Attack Vector**:
  - Embedding operation errors leaked to LLM context
  - Error messages may contain sensitive metadata
  - No sanitization of error details before LLM exposure
  - Can reveal internal paths, API keys, or configuration
- **Impact**: Limited information disclosure, reconnaissance aid
- **Exploitation**:
  1. Trigger embedding errors via malformed memory queries
  2. Error details leaked into LLM conversation context
  3. Extract internal implementation details from error messages

---

## Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| CRITICAL | 2-3   | 20-30%     |
| HIGH     | 5-6   | 50-60%     |
| MEDIUM   | 2-3   | 20-30%     |
| LOW      | 1     | ~10%       |

## Vulnerability Categories

| Category | Count | Examples |
|----------|-------|----------|
| SSRF | 3 | Gemini citations, Cron webhooks, Web_fetch |
| Prompt Injection | 1 | Browser console/snapshot injection |
| RCE | 1 | Nodes system.run approval bypass |
| Access Control | 1 | Sessions cross-agent access |
| Auth Bypass | 1 | Gateway owner spoofing |
| Path Traversal | 1 | Canvas jsonlPath manipulation |
| Data Exfiltration | 1 | Browser upload unsanitized content |
| Info Disclosure | 1 | Memory search error leakage |

## Analysis Coverage

- **Tools Analyzed**: >10 high-risk tools
- **Code Review Scope**: 
  - Browser control mechanisms
  - Network request handlers (web_fetch, web_search)
  - Session management (sessions_*, gateway)
  - File system operations (canvas, browser upload)
  - Execution tools (nodes, cron)
  - Memory/data persistence
- **Dataflow Tracing**: Complete chain from untrusted inputs → intermediate processing → sensitive sinks
- **Helper Function Analysis**: URL validators, path sanitizers, content processors, approval mechanisms

## Recommendations

1. **Immediate Actions** (CRITICAL):
   - Implement cryptographic session validation for gateway owner checks
   - Add approval consumption tracking to prevent reuse in nodes tool
   - Sanitize browser outputs before LLM context injection

2. **High Priority**:
   - Implement strict URL allowlisting for all network tools
   - Add symlink and path traversal protection to file operations
   - Enforce session isolation with cryptographic boundaries
   - Validate and sanitize file contents before upload/transmission

3. **Defense in Depth**:
   - Implement rate limiting and action throttling
   - Add comprehensive input validation at all trust boundaries
   - Enhance error handling to prevent information leakage
   - Deploy sandbox/chroot for file system operations
   - Add webhook URL allowlisting for cron tool

---

**Report Generated By**: AgentXploit Analysis Agent  
**Model Used**: gpt-5.1-codex  
**Analysis Duration**: ~20 minutes  
**Tool Invocations**: 700+ function calls  

