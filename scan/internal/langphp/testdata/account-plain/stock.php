<?php
require 'db.php';
$sku = $_POST['sku'];
$res = mysqli_query($db, "SELECT id FROM products WHERE sku = '$sku'");
if (mysqli_num_rows($res) > 0) {
    echo 'In stock';
    exit;
}
echo 'Sold out';
