<?php
require_once 'queries.php';

$c = pg_connect('host=db');
pg_query($c, Queries::byId() . $_GET['id']);
pg_query($c, USERS_SQL . $_GET['name']);
pg_query($c, find_posts($_GET['author']));
