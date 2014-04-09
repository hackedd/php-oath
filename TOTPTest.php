<?php

require_once "TOTP.php";

class TOTPTest extends PHPUnit_Framework_TestCase
{
    /* The test vectors used in this test are taken from RFC 6238 Appendix B.
     */
    public function testTestVectors()
    {
        $keys = array(
            TOTP::SHA1 =>   "12345678901234567890",
            TOTP::SHA256 => "12345678901234567890" . "123456789012",
            TOTP::SHA512 => "12345678901234567890" . "12345678901234567890" .
                            "12345678901234567890" . "1234",
        );

        $testVectors = array(
            TOTP::SHA1 => array(
                59          => "94287082",
                1111111109  => "07081804",
                1111111111  => "14050471",
                1234567890  => "89005924",
                2000000000  => "69279037",
                20000000000 => "65353130",
            ),
            TOTP::SHA256 => array(
                59          => "46119246",
                1111111109  => "68084774",
                1111111111  => "67062674",
                1234567890  => "91819424",
                2000000000  => "90698825",
                20000000000 => "77737706",
            ),
            TOTP::SHA512 => array(
                59          => "90693936",
                1111111109  => "25091201",
                1111111111  => "99943326",
                1234567890  => "93441116",
                2000000000  => "38618901",
                20000000000 => "47863826",
            ),
        );

        foreach ($testVectors as $hash => $values)
        {
            $totp = new TOTP($keys[$hash], 8);
            $totp->setHash($hash);

            foreach ($values as $time => $otp)
            {
                $totp->setCounter($time);
                $this->assertEquals($otp, $totp->generate(), "$hash $time");
            }
        }
    }
}
