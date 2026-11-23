<?php
$conn = mysqli_connect('localhost', 'app', 'secret', 'app');
$sql = "UPDATE members SET label = '" . $_POST['label'] . "' WHERE id = " . $_SESSION['uid'];
mysqli_query($conn, $sql);
