<?php

namespace SoftRog\StatelessAuth\Authentication;

class Validator extends BaseAbstract
{

  public function validate($token, $headers)
  {
    $pattern = "/^HMAC-(?<algorithm>[^ ]+)\s*"
            . "Credential=(?<id>[^\/]+)\/(?<time>\d+),\s*"
            . "SignedHeaders=(?<signed_headers>[^,]+),\s*"
            . "Signature=(?<signature>[^\s]+)\s*$/";

    if ($token && preg_match($pattern, $token, $matches)) {
      $headers = $this->getRequest()->headers;
      $data = array_reduce(explode(';', $matches['signed_headers']), function ($carry, $item) use ($headers) {
        return $carry . $headers->get($item);
      });

      $algorithm = $matches['algorithm'];
      $id = $matches['id'];
      $key = $this->keyGetter->get($id);
      $time = $matches['time'];
      $hmac = $matches['signature'];

      $this->reset($algorithm);
      $this->manager->ttl($this->get('ttl'));
      $this->manager->key($key);
      $this->manager->data($data);
      $this->manager->time($time);

      if ($this->manager->isValid($hmac)) {
        return true;
      }
    }

    return false;
  }

}
