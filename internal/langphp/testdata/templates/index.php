<?php
use Twig\Environment;
use Twig\Loader\ArrayLoader;

$twig = new Environment(new ArrayLoader([]));
$source = "<h1>" . $_GET['name'] . "</h1>";
echo $twig->createTemplate($source)->render([]);
echo $twig->createTemplate("<h1>{{ name }}</h1>")->render(['name' => $_GET['name']]);
