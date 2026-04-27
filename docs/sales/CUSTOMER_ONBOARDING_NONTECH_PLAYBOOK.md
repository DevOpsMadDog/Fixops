# ALdeci Customer Onboarding Playbook
## Non-Technical Click-by-Click Guide: 4 Apps + 8 Integrations (Day 0 to Day 5+)

**Audience:** Sales Engineers, Customer IT Helpdesk, Customer Success
**Scenario:** Customer has 4 production apps. Existing tools: Snyk, SonarQube, JIRA, ServiceNow, CrowdStrike Falcon, AWS, Tenable, Splunk.
**Goal:** Real live data flowing into ALdeci's 6 hero screens within 5 days.
**Version:** 2026-04-27

---

> IMPORTANT — NO FAKE DATA RULE
> Every step in this playbook creates real tenant data through real API calls.
> Never paste seed data directly into a database. Never import from fixture files.
> If a screen is empty after completing a step, that is a signal to investigate
> the connector — not a signal to add demo data. An empty screen with a real
> integration is an honest state. A screen full of fake data is a liability.

---

## Quick Reference: What You Will End Up With

After Day 5 the customer will have:
- 4 production apps enrolled as separate tenants in ALdeci
- 8 external tools pushing or pulling data continuously
- All 6 hero screens populated with findings from their real environment
- A compliance evidence bundle ready to hand to an auditor
- A working Brain Pipeline that runs Multi-LLM consensus on every new finding

The six hero screens you are building toward:

| Screen | URL path | What it shows |
|--------|----------|---------------|
| Command | `/` | KPI dashboard — open criticals, MTTT, compliance %, system health |
| Issues | `/issues` | All findings from all tools, unified and prioritized |
| Brain | `/brain` | 12-step pipeline running on live findings |
| Compliance | `/compliance` | Framework coverage bars + evidence vault |
| Assets | `/assets` | Interactive graph of apps, dependencies, cloud resources |
| Admin | `/admin` | Connectors health, system status, user management |

---

## Infrastructure Checklist — Verify Before Scheduling Day 0

Hand this list to the customer's IT team at least 72 hours before Day 0.
If anything is missing, Day 0 will not complete on schedule.

**Server requirements (one VM or bare-metal Linux host):**
- CPU: 16 vCPU or more
- RAM: 32 GB or more
- Disk: 200 GB free on the partition where Docker stores images
- OS: Ubuntu 20.04 LTS, Ubuntu 22.04 LTS, or RHEL 8/9
- Docker Engine 24.0 or later (not Docker Desktop — the server edition)
- Docker Compose v2.20 or later
- The `docker` command must work without `sudo` (add the install user to the `docker` group)

**Network ports that must be open inbound on the host:**
- 80 (HTTP — redirects to HTTPS)
- 443 (HTTPS — the main UI and API)
- 5432 (PostgreSQL — only if another internal system needs direct DB access; otherwise keep closed)
- 8000 (internal API — only needed if your reverse proxy is on a separate host)

**DNS:** The host must have a fully qualified hostname that resolves from the laptops of everyone who will use ALdeci. Example: `aldeci.company.internal`. Self-signed TLS is acceptable for evaluation; production deployments should use a certificate from your internal CA or Let's Encrypt.

**Outbound internet access (can be restricted to specific destinations):**
- Required for pulling Docker images on first install: `registry-1.docker.io`, `ghcr.io`
- Required for threat intel feeds: specific URLs provided in the feed-config file delivered with your bundle
- If deploying in fully air-gapped mode: contact your ALdeci SE — a separate air-gap bundle with pre-loaded images exists and uses the same install script with zero internet calls

---

## Part 1: Day 0 — Deploy ALdeci (Allow 2 to 4 Hours)

### 1.1 Receive the Secure Delivery Bundle

Your ALdeci Sales Engineer will deliver one of the following before Day 0:

**Option A — Vendor Portal Download (most customers)**
You will receive an email from `delivery@aldeci.io` with a one-time signed link.
Click the link. You will land on a download page showing a file named:
`aldeci-bundle-YYYY-MM-DD.tar.gz` plus a file named `aldeci-bundle-YYYY-MM-DD.tar.gz.sha256`

Download both files to the server. Example using the terminal:
```
wget "https://delivery.aldeci.io/bundle/aldeci-bundle-2026-04-27.tar.gz"
wget "https://delivery.aldeci.io/bundle/aldeci-bundle-2026-04-27.tar.gz.sha256"
```

**Option B — Air-Gap USB Delivery**
The SE will hand-deliver a hardware-encrypted USB. Plug it in. Copy both files (bundle + sha256) to `/opt/aldeci-install/`.

**What you expect to see after download:**
Two files in the same directory. Nothing else is needed yet.

---

### 1.2 Verify the SHA-256 Manifest

This step proves the file was not corrupted or tampered with in transit.
Run this command in the directory where you saved the files:

```
sha256sum --check aldeci-bundle-2026-04-27.tar.gz.sha256
```

**Expected output:**
```
aldeci-bundle-2026-04-27.tar.gz: OK
```

**What if it fails (output says FAILED):**
Stop. Do not proceed. Contact your SE immediately on the shared Slack channel.
Either the download was interrupted (try downloading again) or there is an integrity problem that must be investigated before proceeding.

---

### 1.3 Extract the Bundle

```
mkdir -p /opt/aldeci
tar -xzf aldeci-bundle-2026-04-27.tar.gz -C /opt/aldeci
cd /opt/aldeci
```

You should now see a directory structure including `scripts/`, `docker/`, and `docs/`.

---

### 1.4 Run the Day 1 Install Script

This single command does everything: loads Docker images, creates the database, generates your first admin API key, and starts all services.

For most customers (non-SCIF, non-air-gap), run:

```
sudo bash scripts/scif_pilot_day1_install.sh --dev-mode
```

The `--dev-mode` flag tells the installer to skip FIPS-140 hardware module requirements that only apply to classified government environments. For commercial customers this flag is correct and required.

**What the script does (you will see these steps scroll by):**

1. Checks that your server meets all prerequisites (Docker version, disk space, open ports)
2. Loads Docker images from the bundle (no internet needed for images)
3. Creates the PostgreSQL database and runs the first schema migration
4. Generates a unique admin API key and writes it to `/var/log/aldeci-scif-day1.log`
5. Starts all ALdeci containers using Docker Compose
6. Runs a self-test to verify every service is responding
7. Prints a summary table

**How long it takes:** 15 to 45 minutes depending on server speed. The longest step is loading Docker images on first install.

**Expected output at the end:**
```
[  OK  ] All 6 services healthy
[  OK  ] Admin API key written to install log
[  OK  ] Day-1 install complete
```

**What if it fails:**

| Error message | What to do |
|---------------|------------|
| `docker: command not found` | Install Docker Engine: `curl -fsSL https://get.docker.com | sh` |
| `Port 443 already in use` | Another service (often nginx or Apache) is using port 443. Stop it: `sudo systemctl stop nginx` or `sudo systemctl stop apache2`, then re-run the script. |
| `Port 5432 already in use` | An existing PostgreSQL is running. Either stop it (`sudo systemctl stop postgresql`) or contact your SE to configure ALdeci to use a different port. |
| `SELinux: Permission denied` | Run `sudo setenforce 0` to set SELinux to permissive mode for the install. Ask your security team if a permanent policy exception is appropriate. |
| `No space left on device` | The Docker partition is full. Run `docker system prune` to remove old images, then re-run the script. |
| `Failed to resolve hostname` | DNS is not configured. Set `/etc/hosts` to map `aldeci.company.internal` to `127.0.0.1` for a local test, or configure proper DNS. |
| Script exits at step 5 with exit code 50 | Docker Compose failed. Run `docker compose -f /opt/aldeci/docker/docker-compose.yml logs` to see which container failed and why. Share the output with your SE. |

---

### 1.5 First Admin Login

Open a browser on any laptop that can reach the server.
Navigate to: `https://your-server-hostname/login`

Your initial credentials are in the install log. Find them:
```
sudo grep "INITIAL_ADMIN" /var/log/aldeci-scif-day1.log
```

You will see a line like:
```
INITIAL_ADMIN_EMAIL: admin@aldeci.local
INITIAL_ADMIN_PASSWORD: Ald3ci-2026-xxxxxxxx
```

Type the email and password into the login form. Click **Sign In**.

**Expected outcome:** You land on the Command dashboard (`/`). The dashboard will show zeroes for most KPIs — this is correct. No apps have been connected yet.

**What if login fails:**
- Check that you are using `https://` not `http://`
- Check that your browser is not blocking the self-signed certificate (you will see a "Your connection is not private" warning — click **Advanced** then **Proceed** to accept it for the evaluation period)
- If the credentials from the log file do not work, the installer may have used different defaults. Check for a line containing `PASSWORD` in the install log: `sudo grep -i password /var/log/aldeci-scif-day1.log`

---

### 1.6 Health Check

After logging in, go to: **Admin** (left sidebar, gear icon) then click **System**.

You will see a status panel with 6 rows. Each row should show a green checkmark.

| Service | What it means if green |
|---------|----------------------|
| API Gateway | ALdeci's backend is running and accepting requests |
| Brain Pipeline | The AI reasoning engine is ready |
| Database | PostgreSQL is connected and the schema is current |
| Evidence Chain | Cryptographic signing for audit logs is working |
| Threat Intel | Feed processor is running (findings will get enriched) |
| Queue Worker | Background jobs (scans, sync jobs) are running |

**If any row shows red or yellow:**
Click on the row. A drawer opens with a specific error message and a suggested fix.
If the error mentions a container name (e.g., `aldeci-worker`), run:
```
docker logs aldeci-worker --tail 50
```
Share the output with your SE via the shared Slack channel.

---

### 1.7 Rotate the Admin Password

Do this immediately after the health check. Do not skip this step.

1. Click the circle with your initials in the top-right corner
2. Click **Profile Settings**
3. Click **Change Password**
4. Enter the temporary password from the install log in the **Current Password** field
5. Enter your new password twice (minimum 12 characters, at least one number, one uppercase, one special character)
6. Click **Save**

**Expected outcome:** You are logged out and redirected to the login screen. Log back in with your new password. If login succeeds, password rotation is complete.

---

## Part 2: Day 1 — Onboard 4 Apps (Real Customer Flow)

Each app becomes its own tenant (called an Organization in ALdeci). Tenant isolation means findings from App A are never visible to users of App B unless an admin explicitly grants cross-org access.

The steps below show App 1 in full detail. Apps 2, 3, and 4 follow the same path — a compact summary for each appears at the end of this section.

---

### 2.1 Create a Tenant Organization for App 1

1. In the left sidebar, click **Admin** (gear icon)
2. Click **Organizations**
3. Click the blue **Create New** button in the top-right corner
4. Fill in the form:
   - **Organization Name:** Use a clear name that matches how your team refers to the app. Example: `Payment Service` or `Customer Portal`. This is what appears in every report.
   - **Classification Level:** Select `INTERNAL` for most commercial apps. Select `CONFIDENTIAL` if the app handles regulated data (PCI scope, HIPAA PHI, etc.).
   - **Organization Slug:** ALdeci auto-fills this as a lowercase version of the name. You can edit it. It cannot be changed after creation. Example: `payment-service`
5. Click **Create Organization**

**Expected outcome:** The Organizations list refreshes and shows your new org. The row shows `Status: Provisioning` for about 10 seconds, then changes to `Status: Active`.

**What if it fails (409 Conflict):** The slug is already in use by another org in the system. Change the slug slightly — add a number or your company prefix. Example: `acme-payment-service`.

---

### 2.2 Generate a Tenant API Key

Every connector and sync job needs an API key scoped to the tenant.

1. Still in **Admin**, click **Tokens**
2. Click **Create Token**
3. Fill in:
   - **Name:** Something you will recognize. Example: `App1 Connectors - Day 1`
   - **Organization:** Select the org you just created from the dropdown
   - **Expiry:** Set to 90 days for evaluation; set to 1 year for production
4. Click **Create**
5. A dialog shows the full token. **Copy it immediately.** It will never be shown again.
   Paste it into your onboarding notes document or a password manager. You will use it in every connector step for this app.

**Expected outcome:** Token appears in the Tokens list with status `Active`.

---

### 2.3 Connect the Source Code Repository

ALdeci needs to read the source code to run its native SAST, secrets detection, and dependency scanners. Choose the section matching the customer's SCM.

**GitHub (most common):**

1. Go to **Admin** then **Connectors** then click **Add Connector**
2. Select **GitHub** from the connector type list
3. Click the **Install ALdeci GitHub App** button — this opens GitHub in a new tab
4. On GitHub, click **Install** and select the repositories you want ALdeci to scan
5. GitHub redirects back to ALdeci automatically
6. Back in ALdeci, in the connector form:
   - **Organization:** Select the org you created in step 2.1
   - **API Token:** Paste the tenant API key from step 2.2
   - **Repository:** Select the specific repository from the dropdown (populated automatically after the GitHub App install)
7. Click **Save and Test Connection**

**GitLab:**

1. In GitLab, go to your profile avatar (top-right) then **Edit Profile** then **Access Tokens**
2. Click **Add New Token**. Name it `ALdeci`. Select scopes: `read_repository`, `read_api`. Set expiry 1 year. Click **Create Personal Access Token**.
3. Copy the token immediately. Go back to ALdeci.
4. In ALdeci: **Admin** then **Connectors** then **Add Connector** then select **GitLab**
5. Fill in:
   - **GitLab URL:** Your GitLab instance URL. Example: `https://gitlab.company.com`
   - **Personal Access Token:** Paste the token from GitLab
   - **Project Path:** The full path. Example: `mygroup/myproject`
   - **Organization:** Select the org you created
6. Click **Save and Test Connection**

**Bitbucket:**

1. In Bitbucket, click your avatar then **Personal Settings** then **App Passwords**
2. Click **Create app password**. Name it `ALdeci`. Select permissions: `Repositories: Read`. Click **Create**.
3. Copy the app password.
4. In ALdeci: **Admin** then **Connectors** then **Add Connector** then select **Bitbucket**
5. Fill in: **Workspace** (your Bitbucket workspace name), **App Password** (from above), **Repository Slug** (the repo name as it appears in the URL)
6. Click **Save and Test Connection**

**Azure DevOps:**

1. In Azure DevOps, click your avatar (top-right) then **Personal Access Tokens**
2. Click **New Token**. Name it `ALdeci`. Scope: `Code: Read`. Expiry: 1 year. Click **Create**.
3. Copy the token.
4. In ALdeci: **Admin** then **Connectors** then **Add Connector** then select **Azure DevOps**
5. Fill in: **Organization URL** (example: `https://dev.azure.com/mycompany`), **Project Name**, **PAT** (paste from above)
6. Click **Save and Test Connection**

**Expected outcome for all SCM types:**
The connector row shows `Status: Connected` with a green dot.
If the test fails, the most common cause is an incorrect token scope. Re-read the scope requirements above and regenerate the token with exactly those scopes.

---

### 2.4 Trigger the First Sync

1. Go to **Admin** then **Connectors**
2. Find the connector you just created. Click the three-dot menu on the right side of its row.
3. Click **Trigger Sync Now**
4. A progress indicator appears on the row. For a small repo (under 50,000 lines), sync completes in about 2 minutes. For a large repo (over 500,000 lines), allow up to 15 minutes.
5. You can watch live progress at: `https://your-server/admin/connectors` — the row shows the current step (Cloning, Scanning, Ingesting, Complete).

**What the sync does behind the scenes:**
- Clones the repository
- Runs ALdeci's native SAST engine (110+ rules across 8 languages)
- Runs ALdeci's secrets detection engine (200+ credential patterns)
- Runs ALdeci's dependency scanner
- Packages all findings as SARIF and injects them into the Brain Pipeline
- The Brain Pipeline runs 12 steps: normalize, deduplicate, enrich with threat intel, score, run Multi-LLM consensus vote, verify exploitability, generate AutoFix suggestions, create evidence records

**Expected outcome:**
Connector row shows `Last sync: [timestamp]` and `Status: Healthy`.

**What if sync gets stuck:**
If the row shows `Syncing...` for more than 20 minutes, click the connector row to open the detail drawer. Scroll down to **Sync Logs**. The last log line will indicate where it is stuck.
Common causes: repository requires SSH key (configure under Admin → SSH Keys), repository is too large (contact SE to enable incremental scanning mode).

---

### 2.5 Verify Findings Are Flowing

1. Click **Issues** in the left sidebar (the bug icon)
2. Click the **All** tab at the top of the page
3. You should see a non-zero count of findings

**What each finding row shows:**
- Severity badge (CRITICAL, HIGH, MEDIUM, LOW)
- Finding title (example: `SQL Injection in user_input.py:142`)
- Source (which scanner found it — in this case it will say `ALdeci Native SAST`)
- Asset (which repo and file)
- Status (Open, In Progress, Resolved)

**What if the count stays at zero after sync completes:**
This is Bug #4 from the known issues list. The Brain Pipeline reports `completed` but findings may need a manual refresh to appear in the Issues dashboard. Go to **Admin** then **System** then click **Refresh Finding Index**. If findings still do not appear after 2 minutes, contact your SE — this requires a backend fix.

---

### 2.6 Verify the Asset Graph

1. Click **Assets** in the left sidebar (the graph icon)
2. You should see graph nodes representing:
   - Your repository (rectangular node)
   - Dependencies detected by the scanner (circular nodes connected to the repo)
3. Click any node to see its details in a right-side drawer

**Expected outcome:** At least one node for the repository and at least one edge connecting it to a dependency. If the graph is empty but findings exist, wait 2 more minutes for the graph indexer to complete its first pass.

---

### 2.7 Validate the Command Dashboard

1. Click the home icon in the left sidebar to go to the Command dashboard (`/`)
2. You should now see non-zero values in the KPI strip at the top:
   - **Open Critical:** Count of CRITICAL severity findings
   - **MTTT (Mean Time to Triage):** Will show `N/A` until you triage your first finding — that is correct
   - **Compliance %:** Will show a low number at this stage because no compliance frameworks have been configured yet — that is correct
   - **Connected Sources:** Should show 1 (the SCM connector)

The Command dashboard is where your CISO will land every morning. It updates in real time as new findings arrive and as the team triages existing ones.

---

### Apps 2, 3, and 4 — Compact Onboarding

**App 2:** Repeat steps 2.1 through 2.7. Create a new organization with a different slug. Generate a new API key scoped to that org. The key from App 1 will not work here — each org has separate access control. Allow 10 to 30 minutes depending on repo size.

**App 3:** Same process. If this app uses a different SCM than App 1 (for example, App 1 was on GitHub and App 3 is on GitLab), follow the GitLab or alternative connector steps in section 2.3. The rest of the flow is identical.

**App 4:** Same process. By this point the team should be moving quickly. If any connector behaves differently from Apps 1-3, check the connector-specific troubleshooting in the Appendix before calling the SE.

**After all 4 apps are onboarded:**
Go to **Admin** then **Organizations**. You should see 4 rows, each `Status: Active`.
Go to **Issues** and use the **Source** filter to confirm findings from each org appear separately.

---

## Part 3: Day 2 to 3 — Wire 8 Existing Tools

This section covers connecting the tools the customer already has. The goal is for ALdeci to be the single place where all findings from all tools are visible together, prioritized by AI consensus rather than by which tool happened to report them loudest.

The general flow for every tool is:
1. Get an API key or credentials from that tool's admin console
2. Go to ALdeci Admin → Connectors → Add Connector → select the tool
3. Fill in the fields, click Test Connection, then Trigger Sync

Each section below gives the exact field names and where to find the values in each tool.

---

### 3.1 Snyk

**What this gives you:** Snyk findings (SCA dependency vulnerabilities, Snyk Code SAST results) flow into the Issues hero alongside ALdeci's native findings. You immediately see the combined view without switching tools.

**Where to get the Snyk API key:**
1. Log into Snyk at `https://app.snyk.io`
2. Click your name or avatar in the top-right corner
3. Click **Account Settings**
4. Scroll to **Auth Token**
5. Click **Click to show** and copy the token — it looks like `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`

**How to connect in ALdeci:**
1. Go to **Admin** then **Connectors** then **Add Connector**
2. Select **Snyk** from the list
3. Fill in:
   - **Organization:** Select the ALdeci org this Snyk account maps to
   - **Snyk API Token:** Paste the token from above
   - **Snyk Org ID:** Back in Snyk, go to **Settings** — your Org ID is shown at the top of that page. Example: `a1b2c3d4-e5f6-7890-abcd-ef1234567890`
4. Click **Test Connection** — you should see `Connection successful, found N Snyk projects`
5. Click **Save**
6. Click the three-dot menu on the connector row then **Trigger Sync Now**

**Which hero screen shows this data:** Issues hero, All tab, with Source filter set to `Snyk`.

**Estimated time:** 10 minutes to connect, 5 to 20 minutes for first sync depending on number of Snyk projects.

---

### 3.2 SonarQube

**What this gives you:** SonarQube code quality and security findings flow into Issues. If the customer has been running SonarQube for years, ALdeci immediately ingests all their existing findings history.

**Where to get the SonarQube token:**
1. Log into your SonarQube instance
2. Click your avatar (top-right) then **My Account**
3. Click the **Security** tab
4. Under **Generate Tokens**, type a name (example: `ALdeci Integration`) and click **Generate**
5. Copy the token immediately — it is shown only once

**How to connect in ALdeci:**
1. **Admin** then **Connectors** then **Add Connector** then select **SonarQube**
2. Fill in:
   - **SonarQube URL:** Your SonarQube server URL. Example: `https://sonarqube.company.com` (no trailing slash)
   - **Token:** Paste the token from above
   - **Project Key:** The key for the specific project. Find it in SonarQube under the project's **Administration** tab, field called **Project Key**. Example: `com.company:myapp`
   - **Organization:** Select the matching ALdeci org
3. Click **Test Connection** — expect `Connected, project found: [project name]`
4. Click **Save** then **Trigger Sync Now**

**Which hero screen shows this data:** Issues hero (code quality findings) and Asset Graph hero (the scanned codebase appears as a Code asset type).

**Estimated time:** 15 minutes.

---

### 3.3 JIRA

**What this gives you:** Two-way sync between ALdeci findings and JIRA tickets. When your security team creates a remediation ticket in ALdeci, it automatically appears as a JIRA issue. When a developer closes the JIRA ticket, ALdeci marks the finding as Resolved. No manual status updates.

**Where to get the JIRA API token:**
1. Go to `https://id.atlassian.com`
2. Click **Security** in the left sidebar
3. Under **API tokens**, click **Create API token**
4. Name it `ALdeci`. Click **Create**. Copy the token.

**How to connect in ALdeci:**
1. **Admin** then **Connectors** then **Add Connector** then select **JIRA**
2. Fill in:
   - **JIRA URL:** Your JIRA cloud URL. Example: `https://mycompany.atlassian.net` — or your on-prem JIRA URL
   - **Email:** The email address of the Atlassian account that owns the API token
   - **API Token:** Paste the token from above
   - **Project Key:** The JIRA project where security tickets should be created. Example: `SEC` or `OPS`. You can find this in JIRA by looking at any issue key — the letters before the hyphen are the project key. Example: if issues are named `SEC-123`, the project key is `SEC`.
   - **Organization:** Select the matching ALdeci org
3. Click **Test Connection** — expect `Connected to JIRA project [PROJECT NAME]`
4. Click **Save** then **Trigger Sync Now**

**How to create a JIRA ticket from ALdeci:**
Go to **Issues**, click any finding row to open the detail drawer. Click **Create Ticket** at the top of the drawer. Select **JIRA**. ALdeci pre-fills the title, description, and severity. Click **Create**. The JIRA issue number appears in the finding row.

**Estimated time:** 20 minutes.

---

### 3.4 ServiceNow

**What this gives you:** ALdeci security incidents flow into ServiceNow as Incidents or Change Requests. When the ServiceNow status changes, ALdeci reflects the change. Useful for teams where ITSM is the system of record.

**Where to get ServiceNow credentials:**
1. You need a ServiceNow service account (not a personal account)
2. Ask your ServiceNow admin to create a user with the `itil` role and the `security_incident_write` role
3. Get: the instance URL (example: `https://mycompany.service-now.com`), the service account username, and the password

**How to connect in ALdeci:**
1. **Admin** then **Connectors** then **Add Connector** then select **ServiceNow**
2. Fill in:
   - **Instance URL:** Your ServiceNow URL as above
   - **Username:** The service account username
   - **Password:** The service account password
   - **Table:** Select `Incident` for security incidents or `Change Request` for remediation workflows
   - **Organization:** Select the matching ALdeci org
3. Click **Test Connection** — expect `Connected to ServiceNow instance [instance name]`
4. Click **Save** then **Trigger Sync Now**

**Estimated time:** 25 minutes (includes time to set up the service account if it does not exist yet).

---

### 3.5 CrowdStrike Falcon

**What this gives you:** Endpoint detection events from CrowdStrike Falcon flow into ALdeci. A finding that appears in both your code scanning tools AND your endpoint tool gets automatically correlated — a much higher-confidence signal than either tool alone. This appears in the Issues hero under the EDR subtab and feeds the Brain Pipeline with runtime context.

**Where to get the CrowdStrike API credentials:**
1. Log into the Falcon console at `https://falcon.crowdstrike.com`
2. Click **Support & Resources** in the top navigation, then **API clients and keys**
   (If you don't see this menu, you need the Falcon Administrator role)
3. Click **Create API client**
4. Name it `ALdeci Integration`
5. Select these permission scopes (exactly these — no more, no less):
   - **Detections:** Read
   - **Event streams:** Read
6. Click **Create**
7. Copy the **Client ID** and **Client Secret** — both are shown once

**How to connect in ALdeci:**
1. **Admin** then **Connectors** then **Add Connector** then select **CrowdStrike Falcon**
2. Fill in:
   - **Client ID:** Paste from above
   - **Client Secret:** Paste from above
   - **Base URL:** Use `https://api.crowdstrike.com` for US-1 cloud. If you are on a different CrowdStrike cloud region, your SE will provide the correct URL.
   - **Organization:** Select the matching ALdeci org
3. Click **Test Connection** — expect `Connected, streaming detections from [tenant name]`
4. Click **Save** then **Trigger Sync Now**

**Which hero screen shows this data:** Issues hero (EDR subtab) and Brain Pipeline (step 8, Contextual Enrichment, will reference the endpoint event in findings that overlap with CrowdStrike hosts).

**Estimated time:** 30 minutes.

---

### 3.6 AWS

**What this gives you:** ALdeci scans your AWS environment for misconfigurations, over-permissive IAM roles, unencrypted storage, public-facing resources, and compliance gaps. This data populates the Compliance hero's Cloud Posture tab and adds cloud resource nodes to the Asset Graph.

**The secure way to connect (IAM Role — recommended):**
An IAM Role is safer than access keys because it does not involve long-lived credentials. Ask your AWS administrator to do the following:

1. Log into the AWS console
2. Go to **IAM** then **Roles** then **Create Role**
3. Select **AWS Account** as the trusted entity type
4. Enter the account ID that your ALdeci team provides (ask your SE — it is the AWS account where ALdeci is running if you chose a cloud deployment, or your own account ID if ALdeci is on-prem)
5. Click **Next** and attach these policies: `SecurityAudit`, `ReadOnlyAccess`
6. Name the role `ALdeci-Scanner` and click **Create Role**
7. Copy the Role ARN — it looks like `arn:aws:iam::123456789012:role/ALdeci-Scanner`

**How to connect in ALdeci:**
1. **Admin** then **Connectors** then **Add Connector** then select **AWS**
2. Fill in:
   - **Connection Method:** Select `IAM Role (recommended)`
   - **Role ARN:** Paste the ARN from above
   - **AWS Region(s):** Select the regions where your apps run. You can select multiple.
   - **Organization:** Select the matching ALdeci org
3. Click **Test Connection** — expect `Connected, found [N] resources in [regions]`
4. Click **Save** then **Trigger Sync Now**

**If your AWS administrator insists on access keys (less recommended):**
In IAM, create a user named `aldeci-scanner` with programmatic access only (no console access), attach the same two policies, and generate access keys. Use `Access Key ID` and `Secret Access Key` in the connector form instead of the Role ARN.

**Which hero screen shows this data:** Compliance hero (Cloud Posture tab showing S3 bucket encryption status, security group rules, IAM policy analysis) and Assets hero (cloud resource nodes with connections to your applications).

**Estimated time:** 40 minutes (includes the time to create the IAM role, which your AWS admin may need to do).

---

### 3.7 Tenable

**What this gives you:** Tenable vulnerability scan results (Nessus-based infrastructure scans, web application scans) flow into ALdeci and get correlated with your code-level findings. A CVE found by Tenable on a production host that also appears in your code gets automatically linked and prioritized higher.

**Where to get the Tenable API keys:**
1. Log into `https://cloud.tenable.com` (or your on-prem Tenable.sc URL)
2. Click your username in the top-right corner
3. Click **My Account**
4. Scroll to **API Keys**
5. Click **Generate** (this generates both an Access Key and a Secret Key at once)
6. Copy both keys immediately — they are shown only once

**How to connect in ALdeci:**
1. **Admin** then **Connectors** then **Add Connector** then select **Tenable**
2. Fill in:
   - **Access Key:** Paste from above
   - **Secret Key:** Paste from above
   - **Tenable URL:** For Tenable.io cloud use `https://cloud.tenable.com`. For on-prem Tenable.sc use your server URL.
   - **Organization:** Select the matching ALdeci org
3. Click **Test Connection** — expect `Connected, found [N] scans in workspace`
4. Click **Save** then **Trigger Sync Now**

**Which hero screen shows this data:** Issues hero (All tab with Source filter `Tenable`) and Compliance hero (NIST framework controls map to Tenable findings automatically).

**Estimated time:** 25 minutes.

---

### 3.8 Splunk

**What this gives you:** ALdeci sends decision and alert events to Splunk for your SOC team's SIEM workflow (outbound). Optionally, ALdeci can also receive Splunk log search results as additional context for finding enrichment (inbound). Most customers start with outbound only.

**Setting up outbound (ALdeci sends events to Splunk):**

Getting the Splunk HEC token:
1. Log into Splunk
2. Click **Settings** (top navigation) then **Data Inputs**
3. Click **HTTP Event Collector**
4. Click **New Token**
5. Name it `ALdeci Events`. Click **Next**
6. Set Source Type to `json`. Select the index where security events should go (ask your Splunk admin — usually `security` or `main`). Click **Review** then **Submit**.
7. Copy the token value shown on the confirmation screen.

Getting the Splunk HEC URL: Ask your Splunk admin for the HEC endpoint URL. It typically looks like `https://splunk.company.com:8088` or `https://prd-p-xxxxx.splunkcloud.com:8088` for Splunk Cloud.

Connecting in ALdeci:
1. **Admin** then **Connectors** then **Add Connector** then select **Splunk**
2. Fill in:
   - **Direction:** Select `Outbound (ALdeci sends events to Splunk)`
   - **HEC URL:** Paste the URL from above
   - **HEC Token:** Paste the token from above
   - **Organization:** Select the matching ALdeci org (or leave as Global to send events from all orgs)
3. Click **Test Connection** — ALdeci sends a test event to Splunk. Check in Splunk Search that an event with `source=aldeci` appeared.
4. Click **Save**

After this is configured, every time ALdeci makes a prioritization decision (a finding moves from Open to In Progress, or a Multi-LLM consensus vote completes, or an AutoFix PR is created), that event is streamed to Splunk in real time.

**Setting up inbound (optional — Splunk sends log context to ALdeci):**
Ask your Splunk admin for: the Splunk search head URL (example: `https://splunk.company.com:8089`), a service account username and password with the `search` role. Add these under the same connector in the **Inbound** section.

**Estimated time:** 45 minutes (longer because it requires coordination with your Splunk admin to set up the HEC endpoint if one does not already exist).

---

## Part 4: Day 4 — Walk Through the 6 Hero Screens with Real Data

By Day 4 all 8 tools should be connected and the first sync from each should have completed. Walk through each screen in order. Bring the stakeholder who owns that screen to the walkthrough — the CISO for Command and Compliance, the DevSecOps lead for Brain and Issues, the infrastructure lead for Assets.

---

### Hero 1: Command Dashboard — `https://your-server/`

**Open the page.** You should see:

**KPI strip across the top:**
- **Open Critical:** A number. This is the total count of CRITICAL severity findings across all connected apps and tools that have not been resolved. Clicking this number jumps to the Issues screen filtered to Critical.
- **MTTT:** Mean Time to Triage. How long on average between a finding being discovered and a team member first acknowledging it. After you have triaged a few findings in Day 4, this will populate.
- **Compliance %:** The percentage of compliance controls that are currently met. Low on Day 4 because frameworks have not been fully configured yet — it will increase as you walk through the Compliance screen.
- **ALDECI Health:** Green dot means all 6 backend services are healthy.

**Trend chart:** Shows finding count over time. On Day 4 this will show a spike corresponding to when each connector first synced.

**Top Exposures panel:** Lists the 5 highest-scoring findings across all apps. Click any row to open the finding detail drawer.

**What to click for a drill-in:** Click any number in the KPI strip. Click any row in the Top Exposures panel. Each click opens a detail view that non-technical stakeholders can read without security training — the drawer explains in plain English what the vulnerability is and what it means for the business.

---

### Hero 2: Issues — `https://your-server/issues`

**Open the page.** You should see findings from every connected tool listed in a unified table.

**Tabs at the top:**
- **All:** Every finding from every source
- **SAST:** Code-level findings (ALdeci native + Snyk + SonarQube)
- **Infrastructure:** Cloud and container findings (AWS + Tenable)
- **EDR:** Endpoint findings (CrowdStrike Falcon)
- **Secrets:** Credentials and tokens found in code

**Filters on the left:** Filter by severity, by source tool, by app (org), by assignee, by status.

**What to click for a drill-in:**
Click any finding row. A right-side drawer opens showing:
- Finding title and description in plain language
- **Score breakdown:** A visual explanation of why this finding scored as high as it did — factors include CVSS base score, exploitability (was it verified by MPTE?), asset criticality, and whether the same vulnerability was seen by multiple tools
- **Reachability proof:** If ALdeci's function-level reachability analysis ran, this section shows the call chain from the entry point to the vulnerable code
- **AutoFix suggestion:** The AI-generated code fix with a confidence score
- **Create Ticket:** One-click to create a JIRA or ServiceNow ticket
- **Acknowledge / Override:** Mark the finding as accepted risk or override the severity if you believe the scanner was wrong

**How to read findings as a non-technical person:**
Severity CRITICAL means an attacker could use this to take over the system or steal significant data with no additional barriers. HIGH means likely serious impact but one or more barriers exist. MEDIUM and LOW are real issues but unlikely to cause immediate damage on their own.
The score number (0–100) is comparable across all tools and all finding types — a score of 85 from Tenable and a score of 85 from SonarQube represent the same level of urgency, even though they are different types of findings from different tools.

---

### Hero 3: Brain Pipeline — `https://your-server/brain`

**Open the page.** You see a list of pipeline runs — one entry per finding that has gone through the Brain Pipeline.

**What the Brain Pipeline is:** Every finding that enters ALdeci, from any source, is processed through 12 sequential steps. The pipeline transforms a raw scanner alert into an actionable, verified, AI-prioritized work item. This is the core of what makes ALdeci different from a simple scanner aggregator.

**Click any pipeline run row.** The detail view shows all 12 steps:

1. Connect — finding received from source
2. Normalize — translated to ALdeci's common schema
3. Resolve — matched against known CVE database and threat intel
4. FP-Suppress — false positive filter (is this actually a real issue?)
5. Dedupe — is this the same finding seen by another tool?
6. Graph — connected to the asset graph (which app, which component)
7. Enrich — enriched with threat intel from 28+ feeds
8. Score — risk score calculated using 7 factors
9. Policy — compared against your organization's security policies
10. **Multi-LLM Consensus** — 5 AI models independently evaluate the finding and vote on severity
11. **MPTE Verification** — exploit verification: the AI attempts to confirm the finding is actually exploitable (not just theoretical)
12. Evidence — cryptographically signed record created for compliance audit trail

**Click step 10 (Multi-LLM Consensus).**
You see a voting panel: 5 AI models, each with their independent severity rating and reasoning. The final severity shown in Issues is the consensus outcome — no single model can bias the result. This is the feature no competitor offers: AI disagreement is visible and auditable.

**Why show this to the customer's leadership:**
"When we say a finding is CRITICAL, five independent AI systems agreed. When they disagree, ALdeci escalates for human review instead of making an automated decision. This is not a black box — the reasoning is here."

---

### Hero 4: Compliance — `https://your-server/compliance`

**Open the page.** Two main tabs:

**Cloud Posture tab:**
Shows the results of the AWS scan. You see a breakdown by service (S3, EC2, IAM, RDS, etc.) with pass/fail counts. Red items are misconfigurations that the scan found. Click any red item to see the specific resource and the remediation step.

**Frameworks tab:**
Shows coverage bars for each compliance framework:
- SOC 2
- NIST 800-53
- ISO 27001
- PCI DSS
- HIPAA (if enabled)

Each bar shows what percentage of that framework's controls are currently met based on the findings in ALdeci. A control is considered met if no open HIGH or CRITICAL findings map to that control. As your team resolves findings, these bars go up automatically.

**Evidence Vault (button at top-right of Frameworks tab):**
Click **Evidence Vault** then **Export**. ALdeci generates a compliance evidence bundle: a ZIP file containing a signed record of every finding, every resolution action, every Multi-LLM consensus vote, and every audit event — with a cryptographic hash chain that proves the records have not been modified. This is the file your auditor asks for.

The export takes about 60 seconds for a typical first export. The resulting file is ready to hand directly to an auditor.

---

### Hero 5: Assets — `https://your-server/assets`

**Open the page.** You see an interactive graph canvas. Each node is an asset:
- Rectangle nodes: your applications (the 4 repos you connected)
- Circle nodes: software dependencies
- Cloud-shaped nodes: AWS resources
- Triangle nodes: third-party APIs your apps call

**How to read the graph as a non-technical person:**
Lines between nodes represent dependency or communication relationships. Nodes with a red border have CRITICAL findings. Nodes with an orange border have HIGH findings.

**Chokepoint detection:**
Look for nodes that many other nodes depend on. These are chokepoints — a vulnerability in a chokepoint affects every system that depends on it. ALdeci automatically labels the top 5 chokepoints with a star icon.

**Click any red-bordered node.**
The drawer shows: what the node is, which findings affect it, which other nodes depend on it (blast radius), and the recommended priority order for fixing it.

**Attack path drill-in:**
Click **Show Attack Paths** in the top-right toolbar. Red dashed lines appear showing the paths an attacker could travel from an entry point (a public-facing service) to a sensitive resource (a database, a secret store, an admin panel). Click any path to see the individual steps and which findings must be resolved to break the path.

---

### Hero 6: Admin — `https://your-server/admin`

**Connectors tab:** Shows all 8 integrations with their sync status. Green dot = healthy and syncing. Yellow dot = warning (sync completed but with some errors). Red dot = failed (last sync did not complete). Click any row for details.

**System tab:** The 6 green checkmarks from Day 0. Check this daily for the first week to confirm nothing has drifted.

**Users tab:** Manage team access. Add new users by email. Assign roles:
- **Viewer:** Can see all screens but cannot take actions
- **Analyst:** Can triage findings, create tickets, add comments
- **Engineer:** Can approve AutoFix PRs, configure policies
- **Admin:** Full access including connector configuration and user management

---

## Part 5: Day 5 and Beyond — Daily Operation

### Setting Up Notifications

Go to **Admin** then **Notifications**.

For Slack:
1. Click **Add Integration** then **Slack**
2. Click **Authorize Slack** — this opens Slack's OAuth page. Authorize ALdeci to post to the channel of your choice.
3. Select which events trigger notifications: New Critical finding, Multi-LLM consensus complete, AutoFix PR created, Connector health change.
4. Click **Save**

For email:
1. Click **Add Integration** then **Email**
2. Enter the email addresses to notify (can be a team email alias)
3. Select event types and minimum severity threshold
4. Click **Save**

---

### Acknowledging an Alert

When a new Critical finding arrives:
1. Click the notification link (Slack or email) to open the finding directly
2. Read the plain-language description in the drawer
3. If you agree it needs urgent attention: click **Assign** and select the developer responsible for that codebase
4. If it is a known acceptable risk: click **Accept Risk** and type a brief justification. This is recorded in the audit trail.
5. If you believe the scanner was wrong: click **Override** and select a new severity. The AI learns from your override.

---

### Bulk-Triage 10 or More Findings at Once

1. Go to **Issues** and filter to the findings you want to act on (example: filter by Source=Snyk, Severity=MEDIUM)
2. Click the checkbox in the header row to select all visible findings
3. Click **Bulk Action** at the top of the table
4. Choose: **Assign to...**, **Accept Risk**, **Suppress**, or **Create Tickets**
5. Confirm the action

This is useful at the start of each week when new scan results arrive overnight and you need to quickly separate what needs immediate action from what can be scheduled.

---

### Generating a Compliance Evidence Bundle

1. Go to **Compliance** then click **Evidence Vault** (top-right)
2. Click **Export**
3. Choose the time range (most auditors want the last 12 months or since the last audit)
4. Choose the framework (SOC 2, NIST 800-53, ISO 27001, PCI DSS, or All)
5. Click **Generate Bundle**
6. Wait for the progress bar to complete (30 to 90 seconds)
7. Click **Download**

The downloaded ZIP file contains:
- A human-readable PDF summary
- Machine-readable JSON records for each control
- A `manifest.json` with SHA-256 hashes of every file in the bundle
- A cryptographic signature file that your auditor can use to verify nothing was altered

Hand this file to your auditor. No additional formatting or extraction required.

---

### Escalating a Finding to Multi-LLM Council

For findings where the automated consensus does not feel right:
1. Go to **Brain** and find the finding's pipeline run
2. Click into the pipeline run
3. Click **Step 10: Multi-LLM Consensus**
4. Click **Re-Escalate with Context**
5. A text box appears — add any context you have (example: "This endpoint is behind an authenticated API gateway in our environment")
6. Click **Re-Run Consensus**
7. The 5 AI models re-evaluate with your context added. If the result changes, the audit trail records both the original and updated assessments.

---

## Part 6: Competitive Positioning — One Paragraph Per Competitor

### vs. Apiiro

Apiiro has strong capabilities in risk graph analysis and what they call Deep Code Analysis (DCA) for understanding material code changes. Where ALdeci wins: the 12-step Brain Pipeline combines code analysis, runtime validation, and Multi-LLM consensus into a single automated flow, while Apiiro relies on analyst interpretation of the risk graph. ALdeci's 6-hero consolidated UX means a CISO, a DevSecOps engineer, and an auditor all work in the same product rather than pulling reports into separate views. If the customer already has Apiiro, ALdeci ingests Apiiro's output via the SARIF ingest endpoint (`POST /api/v1/scanner-ingest/upload`) on Day 1, so the customer gets the union of both tool sets without replacing anything. Reference: `docs/competitive_validation_2026-04-26.md` — Apiiro section, Fixops WIN=10, MATCH=8, LOSE=3.

### vs. Aikido

Aikido is a SaaS-only product aimed at developer-first mid-market companies. Their strength is a clean developer UX with fast onboarding (under 5 minutes for a small team). ALdeci wins on everything regulated or on-premises: fully self-hosted, air-gap certified for SCIF environments, 8 native scanners that work with zero internet, and compliance evidence generation with cryptographic signing. A customer that starts on Aikido and then faces SOC 2 or FedRAMP requirements will outgrow it. ALdeci is designed for that outcome from Day 1. Reference: `docs/competitive_validation_2026-04-26.md` — Aikido section, Fixops WIN=14, MATCH=4, LOSE=1 (developer laptop UX — acknowledged gap).

### vs. Wiz

Wiz has the most polished cloud security graph in the market and strong DSPM (data security posture management) capabilities, especially after the Google acquisition. The honest position: if the customer's primary concern is cloud security graph UX, Wiz is mature. ALdeci wins because it also covers application code (SAST, SCA, secrets), runs MPTE exploit verification (something Wiz does not do), generates AutoFix PRs, and operates fully offline. For most enterprise customers, the combination of cloud + code + compliance in one on-premises platform with cryptographic audit trails is worth more than Wiz's graph polish. The recommended pitch: "Keep Wiz for cloud-native teams, add ALdeci as the decision layer that unifies Wiz's cloud findings with your code scanner results." ALdeci can ingest Wiz findings on Day 1. Reference: `docs/competitive_validation_2026-04-26.md` — Wiz section, Fixops WIN=9, MATCH=8, LOSE=7 (most losses are cloud graph polish and DSPM depth).

### vs. Tenable

Tenable's strength is 25 years of Nessus-based vulnerability scanning heritage and deep host-level scan data. ALdeci does not attempt to replace Nessus for infrastructure vulnerability scanning — that battle is not winnable in the short term and not necessary to win. The pitch: "Tenable tells you what CVEs exist on your hosts. ALdeci tells you which of those CVEs actually matters, whether it is exploitable in your environment, what the code-level fix looks like, and generates the compliance evidence automatically." ALdeci ingests Tenable scan results on Day 1 (the connector built in section 3.7 above). The customer keeps their Tenable investment and gets everything Tenable does not provide: AI consensus prioritization, AutoFix, Brain Pipeline, and cross-tool correlation. Reference: `docs/competitive_validation_2026-04-26.md` — Tenable section, Fixops WIN=12, MATCH=5, LOSE=4 (Nessus heritage, host-vuln depth, ACR auto-derivation).

---

## Appendix: Troubleshooting Guide

### A.1 Port Conflict Issues

**Symptom:** Install script fails at step 5 (Docker Compose boot) with a message like `bind: address already in use` for port 443 or 80.

**Diagnosis:**
```
sudo ss -tlnp | grep -E ':80|:443|:5432|:8000'
```
This lists what process is using each port. The output shows the process name and PID.

**Common culprits and fixes:**

| Port | Common culprit | Fix |
|------|---------------|-----|
| 80 / 443 | nginx | `sudo systemctl stop nginx && sudo systemctl disable nginx` |
| 80 / 443 | Apache | `sudo systemctl stop apache2 && sudo systemctl disable apache2` |
| 443 | HAProxy | `sudo systemctl stop haproxy` |
| 5432 | System PostgreSQL | `sudo systemctl stop postgresql` |
| 8000 | Another Python app | Find and stop the process: `sudo kill $(sudo lsof -t -i:8000)` |

After stopping the conflicting service, re-run the install script.

If you cannot stop the conflicting service (for example, port 443 is used by a production load balancer), contact your SE. ALdeci can be configured to listen on non-standard ports (8443 instead of 443, 8080 instead of 80) with an additional configuration flag.

---

### A.2 OAuth Flows Failing (GitHub App Installation, Atlassian Token)

**Symptom:** After clicking "Install ALdeci GitHub App", GitHub redirects back to ALdeci but the connector shows "Authorization failed" or the page shows a blank screen.

**Root causes and fixes:**

1. **Redirect URL mismatch.** GitHub's OAuth flow requires the callback URL to exactly match what is registered. The callback URL must be `https://your-server-hostname/admin/connectors/github/callback`. If your hostname changed between install time and now, this will fail.
   Fix: Go to Admin → System → Configuration and verify that **Base URL** matches the exact URL you use to access ALdeci including the `https://` prefix and no trailing slash.

2. **Self-signed TLS certificate.** Some OAuth flows reject self-signed certificates.
   Fix for evaluation: Use a real certificate from Let's Encrypt. One command: `sudo certbot --nginx -d aldeci.company.internal` (requires the hostname to resolve from the internet for Let's Encrypt validation). If the server is truly internal, use your company's internal CA and import its root certificate into the server's trust store.

3. **Clock skew.** OAuth tokens have short expiry times. If the server clock is more than 5 minutes off from real time, tokens expire before they can be used.
   Fix: `sudo timedatectl set-ntp true` — enables automatic time sync. Verify: `timedatectl status` should show `System clock synchronized: yes`.

**Symptom:** Atlassian API token returns 401 Unauthorized when testing the JIRA connector.

1. Verify you are using the email address associated with the Atlassian account that generated the token (not a different email).
2. Tokens generated at `id.atlassian.com` are for Atlassian Cloud only. If your JIRA is on-premises (Server or Data Center), you cannot use Atlassian Cloud tokens. Generate a token in the on-prem JIRA UI instead: your profile → Security → API Tokens.
3. If you are using JIRA Data Center with SSO, the API token flow may be disabled by your SSO policy. Ask your Atlassian admin to enable **API token authentication** in JIRA Data Center settings.

---

### A.3 Slow Syncs

**Symptom:** A connector sync is taking more than 30 minutes and has not completed.

**Diagnosis steps:**
1. Go to Admin → Connectors, click the connector row, scroll to **Sync Logs**. The last log line shows the current step and how long it has been running.
2. If the last log line says `Cloning repository...` and has not moved: the repository is very large or the network connection to the SCM is slow. For repositories over 1 GB, the clone step alone can take 20+ minutes on a slow network. This is normal.
3. If the last log line says `Running SAST scan...` and has not moved in 10+ minutes: the SAST scan is running but taking longer than expected. Repositories with over 100,000 files will take 15-30 minutes for a full scan. This is normal on first sync.

**Speeding up future syncs:**
After the first full sync, subsequent syncs are incremental — only changed files are re-scanned. Incremental syncs typically complete in 2-5 minutes regardless of repo size.

**If a sync is truly stuck (not progressing for over 60 minutes):**
```
docker logs aldeci-worker --tail 100
```
Look for `ERROR` lines. The most common causes are:
- Out of memory: worker container killed. Fix: add more RAM or increase Docker memory limits in `/opt/aldeci/docker/docker-compose.yml`
- File descriptor limit: `ulimit -n` is too low. Fix: `sudo sysctl -w fs.file-max=1000000` and restart the worker container

---

### A.4 Missing Scopes on API Tokens

**Symptom:** Connector shows `Connected` but findings from that tool do not appear in Issues after sync.

**This almost always means the API token is missing a read scope.** The token was accepted (authentication worked) but when ALdeci tried to pull data, it received 403 Forbidden on the data endpoints.

**How to diagnose:**
Go to Admin → Connectors, click the connector, scroll to **Sync Logs**. Look for lines containing `403` or `Insufficient permissions` or `scope`.

**Required scopes by tool (re-verify these if data is missing):**

| Tool | Required scopes |
|------|----------------|
| Snyk | The token itself has full access — no scope selection. If data is missing, verify the Org ID matches the Snyk organization where your projects live. |
| SonarQube | Token needs `Execute Analysis` permission OR `Browse` permission on the specific project. Check in SonarQube: Administration → Security → Global Permissions. |
| JIRA | Token owner needs Browse Projects + Create Issues permissions in the target project. Check in JIRA: Project Settings → People. |
| CrowdStrike | Must have exactly `Detections: Read` AND `Event streams: Read`. If you see data from detections but not streaming (or vice versa), re-create the API client with both scopes. |
| AWS IAM Role | Must have both `SecurityAudit` and `ReadOnlyAccess` policies attached. A common mistake is attaching only `ReadOnlyAccess` — this misses security-specific APIs. Verify in IAM: Roles → ALdeci-Scanner → Permissions tab. |
| Tenable | The API key owner must have the `Standard` or `Administrator` role in Tenable. The `Scan Operator` role does not have permission to export scan results via API. |

---

### A.5 Splunk Timestamp / Time Zone Drift

**Symptom:** Events from ALdeci appear in Splunk but with the wrong timestamp, making it hard to correlate with other events in the SIEM.

**Root cause:** ALdeci sends all event timestamps in UTC ISO 8601 format (example: `2026-04-27T14:32:00Z`). If Splunk is configured to interpret incoming HEC events as local time, the timestamps will be shifted by your timezone offset.

**Fix in Splunk:**
1. Go to **Settings** then **Data Inputs** then **HTTP Event Collector**
2. Find the ALdeci token and click **Edit**
3. Under **Source type settings**, change the timestamp format to `Automatic` (not `Current time`)
4. In the Source Type definition for `json` (or whatever you set during HEC setup), ensure `TZ = UTC` is set

Alternatively, in your Splunk search, add `| eval _time=strptime(_time, "%Y-%m-%dT%H:%M:%SZ")` after your search to force correct UTC parsing.

**Verification:** In Splunk, search for `source=aldeci earliest=-1h`. The timestamps in the results should match the timestamps you see in ALdeci's Brain Pipeline runs (which display in your browser's local timezone — account for the offset when comparing).

**Symptom:** Events stop arriving in Splunk after a period of time.

**Cause:** HEC tokens expire if your Splunk instance has token expiry enabled.
**Fix:** In Splunk HEC settings, either disable token expiry or set it to a long duration (1 year). Alternatively, configure ALdeci to re-authenticate: Admin → Connectors → Splunk → Edit → click **Re-Authorize**.

---

*Document prepared by ALdeci Sales Engineering, 2026-04-27.*
*Reference artifacts: `docs/competitive_validation_2026-04-26.md`, `docs/scif/`, `docs/multi_tenant_onboarding_results_2026-04-24.md`, `docs/onboarding_ux_bugs_2026-04-24.md`*
*Canonical onboarding API flow: `docs/multi_tenant_onboarding_results_2026-04-24.md` (15-tenant validation, 9,926 real findings, 100% success rate)*
