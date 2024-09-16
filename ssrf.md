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

## Exploiting and Learning SSRF

We will talk about the SSRF vulnerability, which is classified as critical or high severity in bug bounty programs. I will also go over various testing techniques for swiftly locating SSRFs, and we will conclude with a rudimentary SSRF PortSwigger lab.

### SSRF: What is it?

Server-Side Request Forgery, or SSRF, is a technique that enables an attacker to send a forged request to a server that is vulnerable in order to send an unexpected request to an internal server and obtain access to that internal server.

The attacker can connect to the internal server through the public server (trusted server) by using this SSRF vulnerability.

Because the website's internal server typically won't accept requests directly from users or attackers, but it will allow requests made from the internal server to the public-facing server (which is accessible by anyone).

### In what way do you define "internal server"?

Consider any website, such as Instagram, Facebook, or YouTube, where you can sign in by entering your username and password. Now, because only that website has access to an internal database, how does this website verify that your username and password are correct?

This is known as SSRF when an attacker uses a public website to seek access to a remote internal database, provided the database is available.

The scenario above is only an illustration of the different types of SSRFs; it is not a confirmation of the internal server.

### There are two varieties of SSRFs.

1. Standard SSRF
2. Blind SSRF

### Standard SSRF

An attacker can send queries to internal resources from the targeted server and directly receive the responses in a standard SSRF vulnerability. This implies that the attacker has access to the response's content, which they can use to ascertain whether the SSRF vulnerability is present and perhaps extract sensitive data.

### Blind SSRF

An attacker can also send requests to internal resources through a blind SSRF vulnerability, although they do not receive the answers directly. This could be the result of a number of things, like security mechanisms blocking the response or the server not providing the attacker with the response. Blind SSRF is still a vulnerability even when it doesn't get the responses directly because it lets the attacker interact with internal resources, potentially exploiting other vulnerabilities or carrying out destructive operations inadvertently.

### Finding SSRF

The best method to identify SSRF is to examine the website's source code, although it's still okay if you can't access that.

### Spot feature that is vulnerable to SSRF.

1. Less visible locations that are contained in files, such as PDFs or XML, can frequently cause an SSRF.

   **Note:** Most testers didn't like this location.

2. The input that is placed inside the HTML tag.

3. Determine the functionality that an application action needs in order to cause another action.

4. Verify the concealed API within the message body (Post request).

### Possible Location for SSRF
    
1. XML, PDF, or Documents (This most obscure characteristic)
2. File upload, proxy, and webhook services

### Next, use internal IPs to confirm that vulnerability.

Initially, check if any interactions are resurfacing in the poll or log if you have access to Burpsuite Pro or Ngrok.

Common IP: `10.0.0.1` and `127.0.0.1` for localhost.

[Reserved IP Address List](https://en.wikipedia.org/wiki/Reserved_IP_addresses).

### Verify the response

1. It is a standard SSRF if you receive a response claiming that private or banner data has been leaked.
2. If you don't hear back, proceed to the blind SSRF.

### Outside the Band Methods

Some out-of-band techniques exist to detect Blind SSRF; however, we must have the server's interaction in order to do so.

First, configure the server to receive the log or interaction. Occasionally, during that exchange, the banner data in your log is disclosed.

1. Burpsuite Pro Collaborator
2. Hosting the website on online services like Godaddy
3. Netcat
4. Ngrok
5. If you don’t have the burp collaborator, don’t worry, use this interactsh: [https://github.com/projectdiscovery/interactsh](https://github.com/projectdiscovery/interactsh)

This is one incredible tool in comparison to the collaborator.

In my view, you should check all four of these methods because occasionally they block the burp and netcat in order to prevent problems.

### Basic Lab for PortSwigger SSRF

[PortSwigger Lab - Basic SSRF](https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-localhost).

Let's now proceed to the basic PortSwigger SSRF lab in order to illustrate this weakness.

A stock check feature in this lab retrieves information from an internal system.

Change the stock check URL to `http://localhost/admin` to access the admin interface and remove the user `carlos` in order to complete the lab.

To count the stock of that product, first access the stock check functionality (during testing, you must comprehend the functionality).
