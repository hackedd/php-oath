<?php

require_once "HOTPError.php";
require_once "bcutil.php";

/**
 * This class implements the algorithm outlined in RFC 4226:
 * HOTP: An HMAC-Based One-Time Password Algorithm.
 */
class HOTP
{
    const SHA1 = "sha1";
    const SHA256 = "sha256";
    const SHA512 = "sha512";

    /** @var string the shared key */
    protected $key;

    /** @var string the current counter (as a decimal string) */
    protected $counter;

    /** @var int number of digits in OTP */
    protected $digits;

    /** @var int window size for resynchronization protocol */
    protected $windowSize = 5;

    /**
     * The hash function to use for the HMAC. HOTP implementations should use
     * SHA-1. SHA-256 and SHA-512 may be used for TOTP.
     * @var string
     */
    protected $hash = self::SHA1;

    public function __construct($key, $counter = "0", $digits = 6)
    {
        $this->key = $key;
        $this->counter = $counter;
        $this->digits = $digits;
    }

    /**
     * @param string $counter
     */
    public function setCounter($counter)
    {
        $this->counter = $counter;
    }

    /**
     * @return string
     */
    public function getCounter()
    {
        return $this->counter;
    }

    /**
     * @param int $digits
     */
    public function setDigits($digits)
    {
        $this->digits = $digits;
    }

    /**
     * @return int
     */
    public function getDigits()
    {
        return $this->digits;
    }

    /**
     * @param string $key
     */
    public function setKey($key)
    {
        $this->key = $key;
    }

    /**
     * @return string
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * @param int $windowSize
     */
    public function setWindowSize($windowSize)
    {
        $this->windowSize = $windowSize;
    }

    /**
     * @return int
     */
    public function getWindowSize()
    {
        return $this->windowSize;
    }

    /**
     * @param string $hash
     */
    public function setHash($hash)
    {
        $this->hash = $hash;
    }

    /**
     * @return string
     */
    public function getHash()
    {
        return $this->hash;
    }

    /**
     * Get the counter as a 64-bit binary string.
     * @return string
     */
    public function getBinaryCounter()
    {
        return bc_to_binary($this->getCounter(), 64);
    }

    /**
     * Increment the stored counter by one.
     */
    public function increment()
    {
        $this->counter = bcadd($this->counter, "1");
    }

    /**
     * Generate a OTP for the given counter. If the counter value is not
     * given, the internal counter is used and incremented.
     * @param mixed $counter
     * @return string
     */
    public function generate($counter = null)
    {
        if ($counter === null)
        {
            $counter = $this->getBinaryCounter();
            $this->increment();
        }

        return self::generateOTP($this->key, $counter, $this->digits, $this->hash);
    }

    /**
     * Try to validate the user input against the current OTP.
     * If validation fails, the counter is not incremented.
     * @param string $input
     * @return boolean
     */
    public function validate($input)
    {
        $originalCounter = $this->counter;
        for ($i = 0; $i < $this->windowSize; $i += 1)
        {
            $otp = $this->generate();
            if ($otp === $input)
                return true;
        }

        /* Validation of the OTP failed even after resynchronization, reset
         * counter to previous value. */
        $this->counter = $originalCounter;
        return false;
    }

    /**
     * Try to convert a counter value to a 64-bit binary string.
     * The counter value can be an integer, binary string, hexadecimal string
     * or a GMP number resource.
     * @param mixed $counter
     * @return string
     */
    public static function counterToBinary($counter)
    {
        if (is_integer($counter))
        {
            if (PHP_INT_SIZE < 8)
                throw new HTOPError("Counter specified as integer but PHP_INT_SIZE < 8: counter might be truncated.");
            $high = ($counter & 0xFFFFFFFF00000000) >> 32;
            $low = ($counter & 0x00000000FFFFFFFF);
            return pack("NN", $high, $low);
        }

        if (is_string($counter))
        {
            /* If the length is 8 bytes, assume 64-bit binary string. */
            if (strlen($counter) == 8)
                return $counter;

            /* If the length is 16 bytes, assume 64-bit hex string. */
            if (strlen($counter) == 16)
                return pack("H*", $counter);

            throw new HTOPError("Counter specified as string, but length not valid for 64-bit string.");
        }

        if (is_resource($counter))
            return pack("H*", gmp_strval($counter, 16));

        throw new HTOPError("Invalid type " . gettype($counter) . " for counter.");
    }

    public static function dynamicTruncate($string)
    {
        /*
         * DT(String) // String = String[0]...String[n-1]
         *   Let OffsetBits be the low-order 4 bits of String[n-1]
         *   Offset = StToNum(OffsetBits) // 0 <= OffSet <= 15
         *   Let P = String[OffSet]...String[OffSet+3]
         *   Return the Last 31 bits of P
         */

        $offset = ord(substr($string, -1)) & 0x0F;
        $p = substr($string, $offset, 4);
        $v = unpack("N", $p);
        return $v[1] & 0x7FFFFFFF;
    }

    public static function generateOTP($key, $counter, $digits = 6, $hashAlgo = "sha1")
    {
        $hs = hash_hmac($hashAlgo, self::counterToBinary($counter), $key, true);
        $sbits = self::dynamicTruncate($hs);
        $modulo = pow(10, $digits);
        $value = $sbits % $modulo;

        // printf("\nKey:   %d %s\n", strlen($key), bin2hex($key));
        // printf("Counter: %s\n", bin2hex(self::counterToBinary($counter)));
        // printf("HMAC:  %s\n", bin2hex($hs));
        // printf("SBits: %08x\n", $sbits);
        // printf("%08x %% %d => %d\n", $sbits, $modulo, $sbits % $modulo);

        return str_pad($value, $digits, "0", STR_PAD_LEFT);
    }
}
