<?php
namespace App\Service;

class Pinger
{
    public function ping(string $origin): void
    {
        shell_exec('curl -s ' . $origin);
    }

    public function checked(string $origin): void
    {
        if (!$this->accepts($origin)) {
            return;
        }
        shell_exec('curl -s ' . $origin);
    }

    private function accepts(string $origin): bool
    {
        return filter_var($origin, FILTER_VALIDATE_URL) !== false;
    }
}
