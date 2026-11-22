<?php
$conn = mysqli_connect('localhost', 'app', 'secret', 'app');
mysqli_query($conn, "UPDATE members SET label = 'a' WHERE id = 1");
