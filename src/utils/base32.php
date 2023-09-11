<?php


namespace SECURITY_UTILS {

    $base32_dictionary = 'abcdefghijklmnopqrstuvwxyz234567';

    function base32_decode($data) {
        global $base32_dictionary;
        $data = strtolower(rtrim($data, "=\x20\t\n\r\0\x0B"));

        $dataSize = strlen($data);
        $decoded = '';
        $buf = 0;
        $bufSize = 0;

        for ($i=0; $i < $dataSize; $i++) { 
            $c = $data[$i];
            $buf = ($buf << 5) | strpos($base32_dictionary, $c);
            $bufSize += 5;

            while($bufSize > 7) {
                $bufSize -= 8;
                $decoded .= chr(($buf >> $bufSize) & 0xFF);
            }
        }

        return $decoded;
    }
}