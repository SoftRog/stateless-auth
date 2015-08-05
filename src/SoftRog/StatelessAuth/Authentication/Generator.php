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
    if (!$this->configuration->has('id') || !$this->configuration->has('key')) {
      throw new \SoftRog\StatelessAuth\Exception\InvalidStatelessAuthCredentialsException();
    }

    $this->configuration->add('time', time());

    $this->parseSignedHeaders($headers);
    $this->reset($this->configuration->get('algorithm'));
    $this->manager->key($this->configuration->get('key'));
    $this->manager->data($this->configuration->get('data'));
    $this->manager->time($this->configuration->get('time'));
    $this->manager->encode();

    $hmac = $this->manager->toArray();

    if ($hmac != null) {
      $this->configuration->add('hmac', $hmac['hmac']);
      return $this->buildToken();
    }

    return null;
  }

  private function parseSignedHeaders($headers)
  {
    $data = "";
    $signedHeaders = $this->configuration->get('signed_headers');
    foreach (explode(';', $signedHeaders) as $signedHeader) {
      $data .= is_array($headers[$signedHeader])? implode(';', $headers[$signedHeader]) : $headers[$signedHeader];
    }

    $this->configuration->add('data', $data);
  }

  private function buildToken()
  {
    return sprintf('HMAC-%s Credential=%s/%s, SignedHeaders=%s, Signature=%s',
            strtoupper($this->configuration->get('algorithm')),
            $this->configuration->get('id'),
            $this->configuration->get('time'),
            $this->configuration->get('signed_headers'),
            $this->configuration->get('hmac')
    );
  }

}
