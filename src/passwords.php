<?php


namespace SECURITY {

    class Password {

        private string $key;
        private ?string $password;
        private int $cost = 11;

        public function __construct(?string $key = null, int $cost = 11) {
            if($key === null) {
                $key = $this->generate_key();
            }
            $this->key = $key;
            $this->password = null;
            $this->cost = $cost;
        }

        public function set_key(string $key) {
            $this->key = $key;
            $this->password = null;
        }

        public function set_cost(int $cost) {
            $this->cost = $cost;
            $this->password = null;
        }

        public function generate_key(int $prehashed_length = 16) : string {
            $key = '';

            for ($i=0; $i < $prehashed_length; $i++) {
                $key .= chr(random_int(33, 126));
            }

            $this->set_key($this->_hash($key));
            return $this->key;
        }

        private function _hash(string $key) : string {
            return password_hash($key, PASSWORD_BCRYPT, array("cost" => $this->cost));
        }

        public function get_password() : string {
            if($this->password === null) {
                $this->password = $this->_hash($this->key);
            }
            return $this->password;
        }

        public function verify_password($password) : bool {
            return password_verify($this->key, $password);
        }
    }
}