<?php

namespace SoftRog\StatelessAuth\Authentication;


class Generator extends BaseAbstract
{
  /**
   * Generate a valid token.
   *
   * @param array $headers
   * @return string|null
   * @throws \SoftRog\StatelessAuth\Exception\InvalidStatelessAuthCredentialsException
   */
  public function generate($headers)
  {
    if (!$this->has('id') || !$this->has('key')) {
      throw new \SoftRog\StatelessAuth\Exception\InvalidStatelessAuthCredentialsException();
    }

    $this->reset($this->get('algorithm'));

    $data = "";
    $signedHeaders = $this->get('signed_headers');
    foreach (explode(';', $signedHeaders) as $signedHeader) {
      $data .= is_array($headers[$signedHeader])? implode(';', $headers[$signedHeader]) : $headers[$signedHeader];
    }

    $time = time();

    $this->manager->key($this->get('key'));
    $this->manager->data($data);
    $this->manager->time($time);
    $this->manager->encode();

    $hmac = $this->manager->toArray();

    if ($hmac != null) {
      return sprintf('HMAC-%s Credential=%s/%s, SignedHeaders=%s, Signature=%s',
              strtoupper($this->get('algorithm')),
              $this->get('id'),
              $time,
              $signedHeaders,
              $hmac['hmac']
      );
    }

    return null;
  }

}
