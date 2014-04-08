<?php

require_once "HOTPError.php";

/**
 * This class implements the algorithm outlined in RFC 4226:
 * HOTP: An HMAC-Based One-Time Password Algorithm.
 */
class HOTP
{
    /* Zero as a 64-bit binary integer. */
    const ZERO = "\x00\x00\x00\x00\x00\x00\x00\x00";

    protected $key;
    protected $counter;
    protected $digits;

    public function __construct($key, $counter = self::ZERO, $digits = 6)
    {
        $this->key = $key;
        $this->counter = $counter;
        $this->digits = $digits;
    }

    public function generate($counter = null)
    {
        if ($counter === null)
        {
            $counter = $this->counter;
            /* TODO: Increment counter. */
        }

        return self::generateOTP($this->key, $counter, $this->digits);
    }

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

        /* TODO: Support GMP and/or BC Math numbers. */

        throw new HTOPError("Invalid type " . gettype($counter) . " for counter.");
    }

    public static function dynamicTruncate($string)
    {
        /*
         * DT(String) // String = String[0]...String[19]
         *   Let OffsetBits be the low-order 4 bits of String[19]
         *   Offset = StToNum(OffsetBits) // 0 <= OffSet <= 15
         *   Let P = String[OffSet]...String[OffSet+3]
         *   Return the Last 31 bits of P
         */
        if (strlen($string) != 20)
            throw new HTOPError("DT input should be 160 bits");

        $offset = ord($string[19]) & 0x0F;
        $p = substr($string, $offset, 4);
        $v = unpack("N", $p);
        return $v[1] & 0x7FFFFFFF;
    }

    public static function generateOTP($key, $counter, $digits = 6)
    {
        $hs = hash_hmac("sha1", self::counterToBinary($counter), $key, true);
        $sbits = self::dynamicTruncate($hs);
        $modulo = pow(10, $digits);

        // printf("\nKey:   %d %s\n", strlen($key), bin2hex($key));
        // printf("Counter: %s\n", bin2hex(self::counterToBinary($counter)));
        // printf("HMAC:  %s\n", bin2hex($hs));
        // printf("SBits: %08x\n", $sbits);
        // printf("%08x %% %d => %d\n", $sbits, $modulo, $sbits % $modulo);

        return $sbits % $modulo;
    }
}
