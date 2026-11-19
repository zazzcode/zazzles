<?php
namespace Basic;

class C
{
	private $method = "GET";
	private $command = null;

	public function __construct($method, $command)
	{
		$this->method = $method;
		$this->command = $command;
	}

	private function check()
	{
		$input = (array) json_decode(file_get_contents('php://input'), TRUE);
		$target = $input['target'];
		exec("ping -c 4 " . $target, $output, $status);
		return $status;
	}

	public function run()
	{
		switch ($this->command) {
			case "check":
				return $this->check();
			default:
				return 0;
		}
	}
}
