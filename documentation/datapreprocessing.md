# Data Preprocessing
First, stat_checker.py is used to check the total unique bug_name and CWE

New reports with bug_name: 32579
New reports with CWE:      31611

4920  Cross-site Scripting (XSS) - Reflected
 4389  Insecure Direct Object Reference (IDOR)
 1976  Business Logic Errors
 1798  Information Disclosure
 1593  Cross-site Scripting (XSS) - Stored
 1439  Open Redirect
 1121  Violation of Secure Design Principles
  899  SQL Injection
  758  Cross-site Scripting (XSS) - Generic
  750  Cross-Site Request Forgery (CSRF)
  597  Improper Authentication - Generic
  562  Cross-site Scripting (XSS) - DOM
  550  Server-Side Request Forgery (SSRF)
  467  Code Injection
  465  HTML Injection
  428  Server Misconfiguration - Subdomain Takeover
  355  Acceptance of Extraneous Untrusted Data With Trusted Data - Cache Poisoning
  340  Path Traversal
  323  OS Command Injection
  229  Denial of Service
  227  Resource Injection
  175  Brute Force
  145  Use of Hard-coded Credentials
  136  Insufficient Session Expiration
  133  Cleartext Storage of Sensitive Information
  122  OWASP-A7-Cross-Site Scripting (XSS)
  120  OWASP-A6-Security Misconfiguration
  110  Not Applicable (CWE-NULL)
  100  Insecure Storage of Sensitive Information
   98  Use of Weak Credentials
   98  Unrestricted Upload of File with Dangerous Type
   97  Information Exposure Through Debug Information
   96  Direct Request
   90  OWASP-2013-A3-Cross-Site Scripting (XSS)
   89  OWASP-2013-A5-Security Misconfiguration
   85  Race Condition
   74  Improper Neutralization of Input Used for LLM Prompting
   73  Cleartext Transmission of Sensitive Information
   73  OWASP-2013-A8-Cross-Site Request Forgery (CSRF)
   68  Command Injection - Generic
   68  Information Exposure Through an Error Message
   66  XML External Entities (XXE)
   64  Privacy Violation
   64  OWASP-A3-Sensitive Data Exposure
   62  Deserialization of Untrusted Data
   54  Information Exposure Through Directory Listing
   52  Use of Default Credentials
   52  OWASP-A5-Broken Access Control
   45  None Applicable
   43  Use of Cache Containing Sensitive Information - Cache Deception
   43  Inadequate Encryption Strength
   42  Cryptographic Issues - Generic
   41  Improper Neutralization of Special Elements Used in a Template Engine - SSTI
   37  Weak Password Mechanism for Forgotten Password
   37  Use of Hard-coded Cryptographic Key
   35  Insufficiently Protected Credentials
   34  HTTP Request Smuggling
   28  Remote File Inclusion
   28  OWASP-2013-A6-Sensitive Data Exposure
   28  OWASP-2013-A1-Injection
   26  OWASP-A1-Injection
   25  Unprotected Transport of Credentials
   25  OWASP-2013-A10-Unvalidated Redirects and Forwards
   24  Permissive Cross-domain Policy with Untrusted Domains (CORS)
   24  OWASP-A2-Broken Authentication
   24  OWASP-2013-A9-Using Components with Known Vulnerabilities
   22  CRLF Injection
   21  Use of Hard-coded Password
   20  Use of Externally-Controlled Format String
   19  Password in Configuration File
   19  OWASP-2013-A2-Broken Authentication and Session Management
   18  LDAP Injection
   17  Clickjacking
   16  Unverified Password Change
   15  Weak Cryptography for Passwords
   14  Plaintext Storage of a Password
   14  Improper Handling of Extra Parameters
   13  Improper Neutralization of Special Elements Used in a Template Engine - CSTI
   13  Server Misconfiguration - DNS Zone Takeover
   12  Use of Insufficiently Random Values
   12  OWASP-2013-A4-Insecure Direct Object References
   10  Improper Authorization
   10  Missing Authorization
   10  Use of Web Link to Untrusted Target with window.opener Access
   10  Improper Neutralization of HTTP Headers for Scripting Syntax
    9  HTTP Response Splitting
    9  OWASP-A9-Using Components with Known Vulnerabilities
    7  Use of a Broken or Risky Cryptographic Algorithm
    7  Improper Certificate Validation
    6  XML Injection
    6  Dependency on Vulnerable Third-Party Component
    6  Storing Passwords in a Recoverable Format
    6  OWASP-2013-A7-Missing Function Level Access Control
    5  Missing Encryption of Sensitive Data
    5  Man-in-the-Middle
    4  Use of a Key Past its Expiration Date
    3  Integer Overflow
    2  Reusing a Nonce, Key Pair in Encryption
    2  Missing Required Cryptographic Step
    2  Out-of-bounds Read
    2  Heap Overflow
    2  Authentication Bypass Using an Alternate Path or Channel
    2  Insertion of Sensitive Information into Log File
    1  Buffer Over-read
    1  Allocation of Resources Without Limits or Throttling
    1  OWASP-A4-XML External Entities (XXE)
    1  Improper Input Validation
    1  Improper Privilege Management
    1  OWASP-A10-Insufficient Logging&Monitoring
    1  Incorrect Calculation of Buffer Size
    1  Double Free
    1  Use After Free
    1  Type Confusion
    1  Use of Unmaintained Third Party Components
    1  Use of Cryptographically Weak PRNG
    1  Off-by-one Error

I noticed that some of the bug_names are identical, with legacy labels, such as the following
XSS - Generic (758)	OWASP-A7-XSS (122), OWASP-2013-A3-XSS (90)
Server Misconfiguration	OWASP-A6-Security Misconfiguration (120), OWASP-2013-A5 (89)
Injection family	OWASP-A1-Injection (26), OWASP-2013-A1-Injection (28)
Improper Authentication - Generic (597)	OWASP-A2-Broken Authentication (24), OWASP-2013-A2-Broken Auth & Session Mgmt (19)
Improper Access Control - Generic (4957)	OWASP-A5-Broken Access Control (52), OWASP-2013-A7-Missing Function Level Access Control (6)
IDOR (4389)	OWASP-2013-A4-Insecure Direct Object References (12)
CSRF (750)	OWASP-2013-A8-CSRF (73)
Information Disclosure (1798)	OWASP-A3-Sensitive Data Exposure (64), OWASP-2013-A6 (28)
Open Redirect (1439)	OWASP-2013-A10-Unvalidated Redirects and Forwards (25)
XXE (66)	OWASP-A4-XXE (1)
Vulnerable components	OWASP-A9 (9), OWASP-2013-A9 (24), Dependency on Vulnerable Third-Party Component (6), Use of Unmaintained Third Party Components (1)

This may be the core issue as to why the CWE does not match the bug_name, as there are legacy labels used prior to the CWE.

After cleaning the data to make sure that the legacy labels match their canonical ones, the match is now closer 
# normalize_hacktivity.py

Before:
New reports with bug_name: 32579
New reports with CWE:      31611
After:
New reports with bug_name: 32579
New reports with CWE:      32423

The 155 difference is the None Applicable and Not Applicable having no CWE


Additionally, there was also the existence of Not Applicable (CWE-NULL) (110) and None Applicable (45). For the purposes of this study, this has been omitted

In order to count the number of reports within the hacktivity I used the new status as a source of truth, initially I wanted to do resolution, where a bug will become new -> accepted -> resolved -> closed before being considered as a report count, however, I noticed that the report status are inconsistent, as some will be new and then closed, or new and then accepted and resolved multiple times, so I simply used new as an estimator.


Next, I realized that the total reported submissions from the stats of the hunters differ from the total reports. 


Initially, I double checked my parsing script in case I missed something, next, I thought the issue might have been in the pagination, so I used hunter_probe.py to check 