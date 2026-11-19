<?php
namespace Dup;

class Runner
{
	private $host;

	public function __construct($host)
	{
		$this->host = $host;
	}

	public function run()
	{
		shell_exec('ping -c 1 ' . $this->host);
	}
}
