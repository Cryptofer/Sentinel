<?php

session_start();
require_once("inc/config.php");
require_once("inc/captcha.class.php");
require_once("inc/sentinel.class.php");

$Sentinel = new Sentinel();

if($Sentinel->validateSession()) {
    die("Sentinel validated");
} else

include "validate.php";

?>