<?php
require __DIR__ . '/lib/Profile.php';

$profile = new Profile();
foreach ($_POST as $k => $v) {
    $profile->$k = $v;
}
$db = new mysqli('localhost', 'app', 'secret', 'app');
$stmt = $db->prepare('UPDATE profiles SET name = ?, role = ? WHERE id = 1');
$stmt->bind_param('ss', $profile->name, $profile->role);
$stmt->execute();
