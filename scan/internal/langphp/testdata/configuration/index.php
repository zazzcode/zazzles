<?php
move_uploaded_file($_FILES['doc']['tmp_name'], 'uploads/' . basename($_FILES['doc']['name']));
