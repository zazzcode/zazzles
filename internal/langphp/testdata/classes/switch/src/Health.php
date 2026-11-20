<?php
namespace Sw;

class Health
{
	private $command;

	public function __construct($command)
	{
		$this->command = $command;
	}

	private function status()
	{
		return "OK";
	}

	private function connectivity()
	{
		$input = (array) json_decode(file_get_contents('php://input'), TRUE);
		exec("ping -c 4 " . $input['target'], $output);
		return $output;
	}

	public function process()
	{
		switch ($this->command) {
			case "status":
				$response = $this->status();
				break;
			case "connectivity":
				$response = $this->connectivity();
				break;
			default:
				$response = "";
		}
		return $response;
	}
}
