<?php
$url = $_GET['u'];
exec("wget -q $url");
