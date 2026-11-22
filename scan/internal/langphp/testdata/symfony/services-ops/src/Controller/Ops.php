<?php
namespace App\Controller;

use App\Reader;
use App\Record;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Process\Process;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Contracts\HttpClient\HttpClientInterface;

class Ops
{
    #[Route('/audit')]
    public function audit(Reader $reader): void {
        $reader->audit();
    }

    #[Route('/quote')]
    public function quote(Reader $reader): void {
        $reader->quote();
    }

    #[Route('/shell')]
    public function shell(Request $request): void {
        Process::fromShellCommandline('convert ' . $request->get('name'));
    }

    #[Route('/argv')]
    public function argv(Request $request): void {
        new Process(['convert', $request->get('name')]);
        new Process(['ls', '-l']);
    }

    #[Route('/use/{record}')]
    public function stored(Record $record): void {
        shell_exec('inspect ' . $record->getSuffix());
    }

    #[Route('/save/{record}', methods: ['POST'])]
    public function save(Request $request, Record $record): void {
        $record->setSuffix($request->files->get('doc')->getClientOriginalExtension());
    }

    #[Route('/remote')]
    public function remote(Request $request, Reader $reader): void {
        $reader->remote($request);
    }

    #[Route('/prefix/{id}')]
    public function prefix(string $id): void {
        file_get_contents('https://api.example.test/v1/' . $id);
    }

    #[Route('/status')]
    public function status(): void {
        file_get_contents('https://api.example.test/status');
    }

    #[Route('/client')]
    public function client(Request $request, HttpClientInterface $client): void {
        $client->request('GET', $request->get('url'));
    }

    #[Route('/curl')]
    public function curl(Request $request): void {
        $handle = curl_init();
        curl_setopt($handle, CURLOPT_URL, $request->get('u'));
    }

    #[Route('/feed/{record}')]
    public function feed(Record $record): void {
        file_get_contents($record->getFeedUrl());
    }

    #[Route('/local')]
    public function local(Request $request): void {
        file_get_contents(__DIR__ . '/../../templates/' . $request->get('p'));
        new BinaryFileResponse(__DIR__ . '/' . $request->get('f'));
    }

    #[Route('/curl/options')]
    public function curlOptions(Request $request): void {
        $handle = curl_init();
        curl_setopt_array($handle, [CURLOPT_URL => $request->get('selected'), CURLOPT_USERAGENT => $request->get('agent')]);
        curl_setopt_array($handle, ['CURLOPT_URL' => $request->get('stringKey')]);
        curl_init($request->get('initial'));
    }

    #[Route('/remove/{record}')]
    public function remove(Record $record): void {
        unlink(__DIR__ . '/records/' . $record->getSuffix());
    }

    #[Route('/optional-destination')]
    public function optionalDestination(Request $request): void {
        $address = $request->get('address');
        if (empty($address)) {
            return;
        }
        file_get_contents($address);
    }
}
