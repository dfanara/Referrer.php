# Referrer.php

Know where your visitors originated from.

Features:

 * Tracks the HTTP Referrers of your guests for 30 days using cookies.
 * Optional Encryption and Verification of cookies.
 * Cookie Encryption: Hide the plaintext data from your users and negate tampering.
 * Hash Verification: Ensure that the stored cookies maintain their integrity.
 * Small and Compact! Only ~200 lines long, including comments for documentation.
 * Licensed under GNU GPL v3

I'm no good at writing sample / filler text, so go write something yourself.

Wondering how to use it? We'll show you! :+1:

First, make sure you include the referrer.php class into your script.


```php
//Instantiate a Referrer object
$referrer = new Referrer([string] cookie_name, [boolean] enable_encryption, [boolean] enable_verification);

//Make sure to run this method on EVERY page, in order to acurately verify the referrer.
$referrer->check_referrer();

//Finally, to retrieve the original referrer use
$referrer->retrieve_referrer();
//to decrypt and verify the cookies if necessary.
//Returns the URL of the referrer, or false if none was found.
```

That's it! There's really nothing to it.

### Dependencies
In order to us Referrer.php, the mcrypt module must be enabled for PHP.

Refferer.php was made by Daniel Fanara, and is licensed under the [GNU GPL v3](http://choosealicense.com/licenses/gpl-3.0/) license.
