<?php

require_once "HOTP.php";

if (!function_exists("hex2bin"))
{
    function hex2bin($hex)
    {
        $string = "";
        for ($i = 0, $n = strlen($hex); $i < $n; $i += 2)
            $string .= chr(hexdec(substr($hex, $i, 2)));
        return $string;
    }
}

class HOTPTest extends PHPUnit_Framework_TestCase
{
    public function counterToBinaryProvider()
    {
        return array(
            array(1,
                  "\x00\x00\x00\x00\x00\x00\x00\x01"),
            array(0x7FFFFFFFFFFFFFFF,
                  "\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF"),
            array("00FFFFFFFFFFFFFF",
                  "\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF"),
            array("\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                  "\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF"),
        );
    }

    /**
     * @dataProvider counterToBinaryProvider
     */
    public function testCounterToBinary($counter, $expected)
    {
        $this->assertEquals($expected, HOTP::counterToBinary($counter));
    }

    public function dynamicTruncateProvider()
    {
        return array(
            array("\x00\x00\x00\x01BBBBBBBBBBBBBBB\x00", 0x00000001),
            array("AAAA\x00\x00\x00\x01BBBBBBBBBBB\x04", 0x00000001),
            array("AAAAAAAA\xFF\xFF\xFF\xFFBBBBBBB\x08", 0x7FFFFFFF),

            /* From RFC 4226, secion 5.4. Example of HOTP Computation for Digit = 6 */
            array(hex2bin("1f8698690e02ca16618550ef7f19da8e945b555a"), 0x50ef7f19),
        );
    }

    /**
     * @dataProvider dynamicTruncateProvider
     */
    public function testDynamicTruncate($string, $expected)
    {
        $this->assertEquals($expected, HOTP::dynamicTruncate($string));
    }

    /* The OTPs tested by this function are generated using `oathtool` from
     * `oath-toolkit` version 2.4.1, which is available at
     * http://www.nongnu.org/oath-toolkit/.
     */
    public function testGenerate()
    {
        $key = hex2bin("00000000000000000000");
        $otps = array("328482", "812658", "073348", "887919", "320986",
                      "435986", "964213", "267638", "985814", "003773",
                      "341298", "818485", "657398", "091297", "820368",
                      "525990", "304831", "129574", "832989", "409881");

        $hotp = new HOTP($key);
        for ($i = 0, $n = count($otps); $i < $n; $i += 1)
            $this->assertEquals($otps[$i], $hotp->generate());

        $key = hex2bin("00112233445566778899");
        $otps = array("184487", "513982", "684146", "973749", "071087",
                      "152601", "642732", "782530", "160578", "633394",
                      "166741", "108425", "750029", "284490", "231296",
                      "242241", "430041", "947563", "962193", "960692");

        $hotp = new HOTP($key);
        for ($i = 0, $n = count($otps); $i < $n; $i += 1)
            $this->assertEquals($otps[$i], $hotp->generate());
    }
}
