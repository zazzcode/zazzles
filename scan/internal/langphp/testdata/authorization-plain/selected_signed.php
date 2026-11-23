<?php
if (!$_SESSION['uid']) {
    exit;
}
$conn = mysqli_connect('localhost', 'app', 'secret', 'app');
$sql = "UPDATE members SET label = '" . $_POST['label'] . "' WHERE id = '" . $_POST['id'] . "'";
mysqli_query($conn, $sql);
