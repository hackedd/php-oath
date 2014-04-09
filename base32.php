<?php

function base32_encode($string)
{
    static $charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    $length = strlen($string);
    $result = "";
    $buffer = ord($string[0]);
    $next = 1;
    $bitsLeft = 8;

    while ($bitsLeft > 0 || $next < $length)
    {
        if ($bitsLeft < 5)
        {
            if ($next < $length)
            {
                $buffer <<= 8;
                $buffer |= ord($string[$next++]);
                $bitsLeft += 8;
            }
            else
            {
                $pad = 5 - $bitsLeft;
                $buffer <<= $pad;
                $bitsLeft += $pad;
            }
        }

        $index = 0x1F & ($buffer >> ($bitsLeft - 5));
        $bitsLeft -= 5;
        $result .= $charset[$index];
    }

    return $result;
}

function base32_decode($string)
{
    $length = strlen($string);
    $buffer = 0;
    $bitsLeft = 0;
    $result = "";

    for ($i = 0; $i < $length; $i += 1)
    {
        $ch = $string[$i];

        /* Skip whitespace. */
        if ($ch == " " || $ch == "\t" || $ch == "\r" || $ch == "\n" || $ch == "-")
            continue;

        /* Deal with commonly mistyped characters. */
        if ($ch == "0") $ch = "O";
        if ($ch == "1") $ch = "L";
        if ($ch == "8") $ch = "B";

        /* Look up the value of this digit. */
        if (($ch >= "A" && $ch <= "Z") || ($ch >= "a" && $ch <= "z"))
            $value = (ord($ch) & 0x1F) - 1;
        else if ($ch >= "2" && $ch <= "7")
            $value = ord($ch) - 24;
        else
            return null;

        $buffer |= $value;
        $bitsLeft += 5;
        if ($bitsLeft >= 8)
        {
            $result .= chr($buffer >> ($bitsLeft - 8));
            $bitsLeft -= 8;
        }
    }

    return $result;
}
