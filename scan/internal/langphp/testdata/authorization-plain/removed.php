<?php
$conn = mysqli_connect('localhost', 'app', 'secret', 'app');
mysqli_query($conn, "DELETE FROM `notes` WHERE id = {$_POST['id']} AND owner = {$_SESSION['uid']}");
