<?php
namespace App\Service;

class ResetNotifier
{
    public function notify(array $addresses, string $code): void
    {
        mail(implode(',', $addresses), 'Reset', 'Code: ' . $code);
    }
}
