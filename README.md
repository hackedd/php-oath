php-oath
========

This is a PHP library containing implementations of the one-time passcode
generators specified in "HOTP: An HMAC-Based One-Time Password Algorithm"
[RFC 4226](https://tools.ietf.org/html/rfc4426) and "TOTP: Time-Based One-Time
Password Algorithm" [RFC 6238](https://tools.ietf.org/html/rfc6238).

Example Usage
-------------

    <?php
    $key = base64_decode("AAAAAAAAAAAAAA==");

    /* This is an event or counter based generator. */
    $generator = new HOTP($key);
    printf("%s\n", $generator->generate());

    /* This is a time-based generator. */
    $generator2 = new TOTP($key);
    printf("%s\n", $generator2->generate());

    /* You can also validate OTPs */
    printf("Valid: %s\n", $generator->validate("073348") ? "Yes" : "No");

    /* For TOTP you can specify the time to use by setting the counter: */
    $generator2->setCounter(strtotime("2008-04-23 17:42:17 UTC"));
    printf("%s\n", $generator2->generate());
