<?php
namespace App;
use Doctrine\ORM\Mapping as ORM;
#[ORM\Entity(repositoryClass: Notes::class)]
class Note {
    #[ORM\Column]
    private string $body;
    #[ORM\Column]
    private string $abstract;
    #[ORM\Column(name: 'bio')]
    private string $biography;
    public function setBody(string $body) { $this->body = $body; }
    public function getBody() { return $this->body; }
    public function getAbstract() { return $this->abstract; }
    public function getBiography() { return $this->biography; }
    public function fill(array $data) {
        foreach ($data as $key => $value) {
            $this->$key = $value;
        }
    }
}
