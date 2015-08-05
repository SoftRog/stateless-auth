<?php

namespace SoftRog\StatelessAuth\AccessKeyGetter\Exception;

class AccessKeyGetterNotFoundException extends \Exception
{
  protected $message = "Access key getter not found.";
}
