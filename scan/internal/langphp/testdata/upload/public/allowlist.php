<?php
// The client extension must be on an allow-list.
$name = $_FILES['doc']['name'];
$ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
if (in_array($ext, ['png', 'jpg'])) {
	move_uploaded_file($_FILES['doc']['tmp_name'], "uploads/" . basename($name));
}
