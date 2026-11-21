<?php
// The destination is outside the served tree.
move_uploaded_file($_FILES['doc']['tmp_name'], "../../private/" . basename($_FILES['doc']['name']));
