<?php

namespace SoftRog\StatelessAuth\AccessKeyGetter\Exception;

class AccessKeyNotFoundException extends \Exception
{
  protected $message = "Access key not found";
}