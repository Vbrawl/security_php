<?php

namespace SECURITY {

    class HOTP {
        private string $key;
        private int $length;
        private int $digits;
        private string $algorithm;

        public function __construct(string $key, int $otp_length = 6, string $algorithm = 'sha1') {
            $this->set_key($key);
            $this->set_otp_length($otp_length);
            $this->algorithm = $algorithm;
        }

        public function set_key(string $key) : void {
            $this->key = \SECURITY_UTILS\base32_decode($key);
        }

        public function set_otp_length(int $otp_length) : void {
            if($otp_length < 6)
                throw new \ValueError("OTP length must be greater than 6.");

            $this->length = $otp_length;
            $this->digits = pow(10, $this->length);
        }

        protected static function int_to_bytestring($value) : string {
            $result = '';
            while($value != 0) {
                $result .= chr($value & 0xFF);
                $value >>= 8;
            }
            $pad_size = strlen($result) % 8;
            return str_repeat("\0", 8 - $pad_size) . strrev($result);
        }

        protected static function dynamic_truncation(string $HS) : string {
            $Offset = ord($HS[-1]) & 0xF;

            return (ord($HS[$Offset]) << 24
                | ord($HS[$Offset+1]) << 16
                | ord($HS[$Offset+2]) << 8
                | ord($HS[$Offset+3])
            ) & 0x7FFFFFFF;
        }


        public function calculate_otp(int $moving_factor) : string {
            $HS = hash_hmac('sha1', $this->int_to_bytestring($moving_factor), $this->key, true);
            echo base64_encode($HS);
            $SNum = $this->dynamic_truncation($HS);

            $code = (string)($SNum % $this->digits);
            $pad_size = $this->length - strlen($code);
            return str_repeat("0", $pad_size) . $code;
        }
    }



    class HOTPCounter extends HOTP {
        private int $counter = 1;

        public function set_counter($counter) : void {
            if($counter < 1)
                throw new \ValueError("Counter must be greater or equal to 1");
            $this->counter = $counter;
        }

        public function reset_counter() : void {
            $this->set_counter(1);
        }

        public function generate_otp(bool $increment_counter = true) : string {
            $otp = parent::calculate_otp($this->counter);
            $this->counter += 1;
            return $otp;
        }
    }

    class HOTPTimer extends HOTP {
        private int $inittime;
        private int $timestep;

        public function __construct(string $key, ?int $inittime = null, int $timestep = 5, int $otp_length = 6, string $algorithm = 'sha1') {
            if($inittime === null) {
                $inittime = time();
            }
            $this->inittime = $inittime;
            $this->timestep = $timestep;
            parent::__construct($key, $otp_length, $algorithm);
        }

        protected function calculate_moving_factor() : int {
            return floor((time() - $this->inittime) / $this->timestep);
        }

        public function generate_otp() : string {
            $moving_factor = $this->calculate_moving_factor();
            return parent::calculate_otp($moving_factor);
        }

        public function verify_otp(string $given_code, int $softness) {
            $moving_factor = $this->calculate_moving_factor();
            for ($i=0; $i <= $softness; $i++) {
                $mf = $moving_factor - $i;
                if($mf <= 0) break;

                if($given_code === parent::calculate_otp($mf))
                    return true;
            }
            return false;
        }
    }

}