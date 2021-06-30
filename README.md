# Sentinel
A very basic PHP-based DDoS protection class. Note, that this will only restrict access to pages where Sentinel has been included. It will work as a very basic request limiter, until the user has created a session for Sentinel. 

## Usage
### Example integration
This repository contains an example usage of Sentinel in the **example** folder. I've integrated my [Icon Captcha for PHP](https://github.com/Cryptofer/icon-captcha) as a validation step, but it's easy enough to integrate Sentinel into any other type of verification measures, be it just a request too.

### In Code

Define the private keys
```
DEFINE("SENTINEL_SECRET", "<secret key>");
DEFINE("SENTINEL_IV", "<16 byte IV>");
```

How you would protect a page with Sentinel.
```
require_once("sentinel.class.php");

$Sentinel = new Sentinel();

if($Sentinel->validateSession()) {
    die("Sentinel session is valid");
} else {
    die("Sentinel session is invalid");
}
```

How you would create a Sentinel session so the user can access the pages.
```
require_once("sentinel.class.php");

$Sentinel = new Sentinel();

$Sentinel->createSession();
```

## Protection
#### Sentinel runs on a very very basic protection algorithm
The session creation steps listed as so.
1. Generate cryptographically random UID with the length of 48 for the requesting user.
2. Create the fingerprint for the user based on his IP Address, User Agent and unique UID. Encrypted with SHA256.
3. Set an expiry time for the token
4. Create a success Checksum with the user's Fingerprint and expiry time, using a symmetric encryption algorithm AES (AES-128-CTR) with the defined keys.
5. Insert the user Checksum & UID in the cookies.

The session validation steps listed as so.
1. Check whether the Checksum or UID is empty or not set in the cookies.
2. Create the fingerprint for the user based on his IP Address, User Agent and unique UID. Encrypted with SHA256.
3. Decrypt the Checksum using the server's private keys and the UID.
4. Validate that the Checksum has indeed been decrypted.
5. Confirm that the Fingerprint within the Checksum matches the newly created Fingerprint.
6. Check whether the expiry time within the Checksum hasn't passed the current time.


