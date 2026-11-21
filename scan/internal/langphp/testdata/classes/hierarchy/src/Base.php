<?php
namespace Tree;

trait Runs
{
	protected function launch($target)
	{
		system('traceroute ' . $target);
	}
}

abstract class Base
{
	use Runs;

	public function __construct(protected string $target)
	{
	}

	public function start()
	{
		$this->launch($this->target);
	}
}

class Child extends Base
{
}

class Orphan extends \Vendor\Missing\Runner
{
}
