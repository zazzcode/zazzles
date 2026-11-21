<?php
namespace Quote;

class Pinger
{
	public function __construct(private string $host)
	{
	}

	public function ping()
	{
		shell_exec('ping -c 1 ' . escapeshellarg($this->host));
	}
}
