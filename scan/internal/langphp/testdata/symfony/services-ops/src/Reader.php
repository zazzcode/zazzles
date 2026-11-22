<?php
namespace App;
use Symfony\Component\HttpFoundation\Request;

class Reader
{
    public function __construct(private bool $enabled) {}
    public function audit(): void {
        if (!$this->enabled) {
            return;
        }
        $origin = $_SERVER['HTTP_REFERER'];
        if (!$this->accepts($origin)) {
            return;
        }
        shell_exec('curl ' . $origin);
    }
    public function quote(): void {
        $origin = $_SERVER['HTTP_REFERER'];
        if (!$this->accepts($origin)) {
            return;
        }
        shell_exec('curl ' . escapeshellarg($origin));
    }
    public function remote(Request $request): string|false {
        return file_get_contents($request->get('url'));
    }
    private function accepts(string $ref): bool {
        return filter_var($ref, FILTER_VALIDATE_URL) !== false;
    }
}
