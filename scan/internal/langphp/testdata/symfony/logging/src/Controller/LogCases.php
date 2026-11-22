<?php
namespace App\Controller;

use Monolog\Logger;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;

class LogCases {
    public function __construct(private LoggerInterface $logger) {}

    #[Route('/log-password')]
    public function password(Request $request) {
        $this->logger->info('login ' . $request->get('password'));
    }

    #[Route('/log-status')]
    public function status() {
        $code = 200;
        $this->logger->info('status: ' . $code);
        $this->logger->info('ready');
    }

    #[Route('/log-authorization')]
    public function authorization(Request $request, LoggerInterface $logger) {
        $logger->error('failed', ['token' => $request->headers->get('Authorization')]);
    }

    #[Route('/log-untyped')]
    public function untyped(Request $request, $logger) {
        $logger->info($request->get('password'));
    }

    #[Route('/log-monolog')]
    public function monolog(Request $request, Logger $logger) {
        $logger->log($request->get('password'), 'ready', ['email' => $request->get('email')]);
    }

    #[Route('/log-builtin')]
    public function builtin(Request $request) {
        error_log($request->getContent());
    }
}
