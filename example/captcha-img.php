<?php
session_start();

require("inc/captcha.class.php");


$Captcha = new Captcha();
$Captcha->getCaptcha();

?>