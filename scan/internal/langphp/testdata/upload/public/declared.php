<?php
// Only the client-declared MIME type is checked.
$type = $_FILES['doc']['type'];
if ($type == "image/png") {
	move_uploaded_file($_FILES['doc']['tmp_name'], "uploads/" . $_FILES['doc']['name']);
}
