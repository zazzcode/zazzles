<?php
namespace App;
class RefreshLabel {
    public function run(Label $label) {
        $label->setCaption('nightly');
    }
}
