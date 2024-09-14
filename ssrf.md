## Server-Side Request Forgery (SSRF): The Web's Hidden Proxy

**Server-Side Request Forgery (SSRF)** is a cunning vulnerability that allows attackers to manipulate a web application into making requests to internal or external resources on their behalf. Imagine a hacker using a web application as a puppet, forcing it to fetch sensitive data or perform actions that it shouldn't.

---

### Understanding SSRF: The Basics

SSRF vulnerabilities arise when a web application fetches a remote resource without properly validating the user-supplied input that specifies the resource location. This allows attackers to craft malicious requests that can bypass firewalls, access internal services, or even execute code on the server.

---

### The Anatomy of an SSRF Attack

- **User Input**: The attacker provides a URL or other identifier as input to the web application, specifying a resource to be fetched.
- **Unvalidated Input**: The web application fails to properly validate or sanitize the input, allowing the attacker to control the target of the request.
- **Server-Side Request**: The web application makes a request to the attacker-supplied URL on behalf of the server.
- **Attacker's Gain**: The attacker can now access resources that are normally inaccessible from the outside, such as internal services, backend APIs, or cloud metadata endpoints.

---

### Types of SSRF Attacks

- **Basic SSRF**: The attacker can access any publicly accessible resource on the internet.
- **Blind SSRF**: The attacker cannot see the response of the server-side request, but can still infer information based on the application's behavior.
- **SSRF with Authentication Bypass**: The attacker can bypass authentication mechanisms to access restricted resources.
- **SSRF to Localhost**: The attacker can access services running on the same server as the web application.
- **SSRF to Cloud Metadata Endpoints**: The attacker can access sensitive information stored in cloud metadata services.

---

### Impact of SSRF Attacks

- **Port Scanning**: Attackers can scan internal networks to discover open ports and services.
- **Service Discovery**: Attackers can identify internal services that are not meant to be exposed to the internet.
- **Information Disclosure**: Attackers can access sensitive data, such as configuration files, source code, or internal APIs.
- **Remote Code Execution (RCE)**: In some cases, attackers can leverage SSRF to execute arbitrary code on the server.

---

### Identifying and Exploiting SSRF Vulnerabilities

#### Manual Testing:
- Look for functionalities that fetch remote resources based on user input (e.g., image fetching, URL previews, webhooks).
- Try injecting different URLs to see if the application makes requests to them.
- Look for ways to bypass filters and WAFs (Web Application Firewalls).

#### Automated Scanning:
- Use web vulnerability scanners like Burp Suite or OWASP ZAP to automate the process of finding SSRF vulnerabilities.

#### Example Payloads:
```plaintext
http://localhost/admin
http://127.0.0.1:8080/
http://169.254.169.254/latest/meta-data/
```

#### Mitigating SSRF Attacks
- **Whitelist Allowed URLs**: Only allow requests to a pre-approved list of safe URLs.
- **Validate User Input**: Sanitize and validate all user-supplied input that is used to fetch remote resources.
- **Network Segmentation**: Isolate internal services from the internet to prevent unauthorized access.
- **Disable Unused Protocols**: Disable protocols that are not needed by the application, such as `gopher://` or `file://`.

# Testing Methodology

## 1. Identify Potential Entry Points:
- Look for functionalities that involve fetching data from remote resources. This includes features like:
  - Image processing or resizing services that fetch images from user-provided URLs.
  - Content aggregation services that fetch articles or news from external sources.
  - File download functionalities that allow users to provide a URL.
  - Webhooks or APIs that accept URLs as input.
  - Social media integrations that fetch data from external platforms.
  - XML parsers or other services that process data from remote sources.

## 2. Craft SSRF Payloads:

### Basic SSRF:
- Replace the original URL with a URL pointing to a server you control:

  ```
  http://your-server.com/test.txt
  ```

  Observe if your server receives a request from the target application's IP address.

### Blind SSRF:
- If you can't see the response directly, try using a service like Burp Collaborator or Interactsh to capture out-of-band interactions.
- Send a request to a Burp Collaborator URL and see if the target application interacts with it.

### SSRF to Localhost/Internal Network:
- Replace the original URL with a URL pointing to localhost or an internal IP address:

  ```
  http://localhost/admin
  http://127.0.0.1:8080/
  http://192.168.0.1/
  ```

  Look for responses that reveal internal services or information.

### SSRF to Cloud Metadata Endpoints:
- Replace the original URL with the cloud provider's metadata endpoint:

  ```
  http://169.254.169.254/latest/meta-data/
  ```

  If vulnerable, the application might leak sensitive information like access keys or instance IDs.

## 3. Bypass Techniques:
- **URL Encoding:** Encode special characters in the URL to bypass filters.
- **Alternative IP Representations:** Use decimal, octal, or hexadecimal representations of IP addresses to bypass filters.
- **DNS Rebinding:** Use a domain that resolves to different IP addresses over time to bypass restrictions based on domain names.

## Real-World Examples:
- **Image Processing Service:** An image processing service allows users to upload images from URLs. An attacker could provide a URL pointing to an internal server, potentially revealing sensitive files or configurations.
- **Webhooks:** A webhook functionality allows users to specify a URL to be notified of events. An attacker could provide a URL pointing to an internal API endpoint, triggering actions or leaking data.
- **XML Parser:** An XML parser that fetches external entities could be exploited to read local files or make requests to internal services.

## Tools:
- **Burp Suite:** Use Burp Suite's proxy and repeater features to intercept and modify requests.
- **SSRFmap:** An automated SSRF fuzzing tool.
- **Kiterunner:** Another automated SSRF testing tool.
- **ffuf:** A fast web fuzzer for finding hidden parameters and endpoints.

---

Always test for SSRF vulnerabilities in a safe and controlled environment. Never exploit vulnerabilities on systems you don't have permission to test.


## SSRF to Internal Services:

- **Scenario:** A web application has a feature to fetch product information from an internal API. The API endpoint is accessible only within the company's network.
- **Payload:** Replace the external product URL with the internal API endpoint (e.g., `http://internal-api.company.com/product/123`).
- **Expected Result:** If vulnerable, the application might return sensitive data from the internal API, such as product prices, inventory levels, or even internal user information.

## SSRF to Backend Systems:

- **Scenario:** A web application uses a backend system like Redis or Memcached for caching or data storage. These systems typically listen on a local port and are not intended to be accessible from the internet.
- **Payload:** Construct a URL that targets the backend system's port and try to interact with it using the application's functionality. For example:
  - **Redis:** `redis://127.0.0.1:6379`
  - **Memcached:** `memcached://127.0.0.1:11211`
- **Expected Result:** If vulnerable, the application might leak sensitive data stored in the backend system or allow the attacker to execute commands on the server.

## SSRF to Cloud Metadata Endpoints:

- **Scenario:** A web application is hosted on a cloud provider like AWS, Azure, or Google Cloud. These providers have metadata endpoints that contain sensitive information about the instance, such as credentials, access keys, and network configuration.
- **Payloads:**
  - **AWS:** `http://169.254.169.254/latest/meta-data/`
  - **Azure:** `http://169.254.169.254/metadata/instance?api-version=2020-09-01`
  - **Google Cloud:** `http://metadata.google.internal/computeMetadata/v1/`
- **Expected Result:** If vulnerable, the application might leak sensitive cloud metadata, potentially allowing an attacker to compromise the entire cloud infrastructure.

## SSRF in File Wrappers:

- **Scenario:** A web application uses PHP's file wrappers (`php://`, `file://`, `data://`) to handle file operations.
- **Payloads:**
  - `php://filter/read=convert.base64-encode/resource=/etc/passwd` (read and encode the `/etc/passwd` file)
  - `data://text/plain,<?php system('id'); ?>` (execute the `id` command)
- **Expected Result:** If vulnerable, the application might execute arbitrary code or leak sensitive file contents.

## Bypassing SSRF Filters:

- **Open Redirects:** Chain an SSRF with an open redirect vulnerability to bypass restrictions on allowed domains.
- **Typosquatting/Homoglyphs:** Use similar-looking domains (e.g., `rnaliy.com` instead of `paypal.com`) to trick the application into making requests to malicious servers.
- **Alternative IP Representations:** Use decimal, octal, or hexadecimal representations of IP addresses to bypass filters that only check for dotted decimal notation.

---

These are just a few examples. SSRF vulnerabilities can be found in various functionalities and contexts. By understanding the different types of SSRF attacks and testing for them creatively, you can uncover critical vulnerabilities and earn substantial bounties.
