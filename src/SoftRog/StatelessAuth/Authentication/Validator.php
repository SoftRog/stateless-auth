<?php

namespace SoftRog\StatelessAuth\Authentication;

use SoftRog\StatelessAuth\AccessKeyGetter\Exception\AccessKeyGetterNotFoundException;
use SoftRog\StatelessAuth\AccessKeyGetter\AccessKeyGetterInterface;

class Validator extends BaseAbstract
{

  /** @var AccessKeyGetterInterface */
  protected $accessKeyGetter;

  /**
   * Set the access key getter.
   *
   * @param AccessKeyGetterInterface $keyGetter
   */
  public function setAccessKeyGetter(AccessKeyGetterInterface $keyGetter)
  {
    $this->accessKeyGetter = $keyGetter;
  }

  /**
   * Get the access key getter if exists or throws an exception otherwise
   *
   * @return AccessKeyGetterInterface
   * @throws AccessKeyGetterNotFoundException
   */
  public function getAccessKeyGetter()
  {
    if (is_null($this->accessKeyGetter)) {
      throw new AccessKeyGetterNotFoundException();
    }

    return $this->accessKeyGetter;
  }

  /**
   * Validate the given $token against the given $remoteHeaders. If it's valid,
   * it returns true, false otherwise.
   *
   * @param string $token
   * @param array $remoteHeaders
   * @return boolean
   */
  public function validate($token, $remoteHeaders)
  {
    $this->reset($this->configuration->get('algorithm'));

    if ($this->parseToken($token) &&
          $this->processSignedHeaders($this->configuration->get('signed_headers'), $remoteHeaders)) {

      $this->configuration->add('key', $this->getAccessKeyGetter()->get($this->configuration->get('id')));

      $this->manager->ttl($this->configuration->get('ttl'));
      $this->manager->key($this->configuration->get('key'));
      $this->manager->data($this->configuration->get('data'));
      $this->manager->time($this->configuration->get('time'));

      if ($this->manager->isValid($this->configuration->get('signature'))) {
        return true;
      }
    }

    return false;
  }

  /**
   * Process the given $signedHeaders using the $remoteHeaders and build a string
   * concatenating the resulting data for the later check.
   *
   * @param array $signedHeaders
   * @param array $remoteHeaders
   * @return boolean
   */
  private function processSignedHeaders($signedHeaders, $remoteHeaders)
  {
    $data = "";
    foreach (explode(';', strtolower($signedHeaders)) as $header) {
      if (!array_key_exists($header, $remoteHeaders)) {
        return false;
      } elseif (is_array($remoteHeaders[$header])) {
        $data .= current($remoteHeaders[$header]);
      } else {
        $data .= $remoteHeaders[$header];
      }
    }

    $this->configuration->add('data', $data);

    return true;
  }

  /**
   * Parse the $token and return the chunks of it
   *
   * @param string $token
   * @return boolean
   */
  private function parseToken($token)
  {
    $pattern = "/^HMAC-(?<algorithm>[^ ]+)\s*"
            . "Credential=(?<id>[^\/]+)\/(?<time>\d+),\s*"
            . "SignedHeaders=(?<signed_headers>[^,]+),\s*"
            . "Signature=(?<signature>[^\s]+)\s*$/";

    if ($token && preg_match($pattern, $token, $matches)) {
      $this->configuration->add('algorithm', $matches['algorithm']);
      $this->configuration->add('id', $matches['id']);
      $this->configuration->add('time', $matches['time']);
      $this->configuration->add('signed_headers', $matches['signed_headers']);
      $this->configuration->add('signature', $matches['signature']);

      return true;
    }

    return null;
  }

}
