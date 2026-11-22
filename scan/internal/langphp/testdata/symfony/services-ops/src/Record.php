<?php
namespace App;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
class Record
{
    #[ORM\Column]
    private string $suffix;
    #[ORM\Column]
    private string $feedUrl;
    public function getSuffix(): string { return $this->suffix; }
    public function setSuffix(string $value): void { $this->suffix = $value; }
    public function getFeedUrl(): string { return $this->feedUrl; }
}
