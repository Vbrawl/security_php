<?php

require_once('relocation.php');
require_once(DATABASE_ADAPTER_PATH.'/main.php');

require_once(SECURITY_PATH.'/src/passwords.php');
require_once(SECURITY_PATH.'/src/utils/base32.php');
require_once(SECURITY_PATH.'/src/hotp.php');
require_once(SECURITY_PATH.'/src/antibruteforce.php');