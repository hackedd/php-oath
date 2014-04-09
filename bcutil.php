<?php

function bc_to_binary($number, $bits = 0)
{
    $bytes = array();
    while ($number != "0")
    {
        $byte = (int)bcmod($number, "256");
        array_unshift($bytes, chr($byte));
        $number = bcdiv($number, "256");
    }

    $string = implode($bytes);
    if (($width = $bits / 8) && strlen($string) < $width)
        $string = str_pad($string, $width, "\0", STR_PAD_LEFT);

    return $string;
}

function hex_to_bc($hex_number)
{
    $s = 0;
    if (substr($hex_number, 0, 2) == "0x")
        $s = 2;

    $value = "0";
    for ($i = $s, $n = strlen($hex_number); $i < $n; $i += 1)
    {
        $value = bcmul($value, "16");
        $value = bcadd($value, hexdec(substr($hex_number, $i, 1)));
    }

    return $value;
}
