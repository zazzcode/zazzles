<?php
use Tree\{Child, Orphan as Lonely};

$child = new Child($_GET['target']);
$child->start();

$orphan = new Lonely($_GET['target']);
$orphan->start();
