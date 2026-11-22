<?php
namespace App\Crypto;

use Symfony\Component\PasswordHasher\PasswordHasherInterface;

final class ShaHasher implements PasswordHasherInterface
{
    public function hash(string $plainPassword): string
    {
        return sha1($plainPassword);
    }

    public function verify(string $hashedPassword, string $plainPassword): bool
    {
        return $this->hash($plainPassword) === $hashedPassword;
    }

    public function needsRehash(string $hashedPassword): bool
    {
        return false;
    }
}
