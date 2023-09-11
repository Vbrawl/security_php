<?php




namespace SECURITY {

    class AntiBruteForce {
        private \DATABASE_ADAPTER\DBAdapter $db;
        private int $tries;
        private string $release_try;
        private string $penalty_duration;

        public function __construct(\DATABASE_ADAPTER\DBAdapter $db, int $tries = 10, string $release_try = '-15 seconds', string $penalty_duration = '+1 minutes') {
            $this->db = $db;
            $this->tries = $tries;
            $this->release_try = $release_try;
            $this->penalty_duration = $penalty_duration;

            $this->setup_database();
        }

        private function setup_database() {
            if(!$this->db->isConnected()) $this->db->connect();
            
            $this->db->exec("CREATE TABLE IF NOT EXISTS `security_antibruteforce_warnings` (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            );");

            $this->db->exec("CREATE TABLE IF NOT EXISTS `security_antibruteforce_penalties` (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                penalized_until DATETIME NOT NULL
            );");
        }

        public function get_warning_count(string $ip_address) {
            if(!$this->db->isConnected()) $this->db->connect();

            $results = $this->db->queryPrepared("SELECT COUNT(id) FROM `security_antibruteforce_warnings` WHERE ip_address=:ip_address AND timestamp > datetime('now', :release_try);", array(':ip_address' => $ip_address, ':release_try' => $this->release_try));
            $result = $results->getRowI();
            return $result[0];
        }

        public function get_penalty_details(string $ip_address) {
            if(!$this->db->isConnected()) $this->db->connect();

            $results = $this->db->queryPrepared("SELECT penalized_until FROM `security_antibruteforce_penalties` WHERE ip_address=:ip_address AND penalized_until > datetime('now');", array(':ip_address' => $ip_address));
            $result = $results->getRowI();

            if($result === false) {
                return array('status' => false, 'until' => '');
            }

            return array('status' => true, 'until' => $result[0]);
        }

        public function add_failed_try(string $ip_address) {
            if(!$this->db->isConnected()) $this->db->connect();

            $this->db->execPrepared("INSERT INTO `security_antibruteforce_warnings` (ip_address) VALUES (:ip_address);", array(":ip_address" => $ip_address));
            if($this->get_warning_count($ip_address) > $this->tries) {
                $this->add_penalty($ip_address);
            }
        }

        public function add_penalty(string $ip_address) {
            if(!$this->db->isConnected()) $this->db->connect();

            $this->db->execPrepared("INSERT INTO `security_antibruteforce_penalties` (ip_address, penalized_until) VALUES (:ip_address, datetime('now', :penalty_duration));", array(':ip_address' => $ip_address, ':penalty_duration' => $this->penalty_duration));
        }

        public function block_if_penalized(string $ip_address) {
            if(!$this->db->isConnected()) $this->db->connect();

            $details = $this->get_penalty_details($ip_address);

            if($details['status']) {
                die("You were blocked.</br>Reason: Too many failed login attempts.</br>Until: ".$details['until']);
            }
        }
    }



}