<?php
// Client name and extension, no type control.
$target = "uploads/" . basename($_FILES['doc']['name']);
move_uploaded_file($_FILES['doc']['tmp_name'], $target);
