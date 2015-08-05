<?php

namespace SoftRog\StatelessAuth\Authentication;

use Mardy\Hmac\Manager;
use Mardy\Hmac\Adapters\Hash;
use SoftRog\StatelessAuth\AccessKeyGetter\AccessKeyGetterInterface;

abstract class BaseAbstract
{
  protected $configuration;

  /** @var Manager */
  protected $manager;

  /** @var KeyGetterInterface */
  protected $keyGetter;

  public function __construct(array $configuration)
  {
    $this->configuration = $this->processConfiguration($configuration);
  }

  public function setAccessKeyGetter(AccessKeyGetterInterface $keyGetter)
  {
    $this->keyGetter = $keyGetter;
  }

  protected function has($name)
  {
    return array_key_exists($name, $this->configuration);
  }

  protected function get($name)
  {
    return $this->configuration[$name];
  }

  protected function processConfiguration(array $configuration)
  {
    $mandatoryKeys = [
      'id',
      'key',
      'ttl',
      'algorithm',
      'signed_headers',
      'num_first_iterations',
      'num_second_iterations',
      'num_final_iterations'
    ];

    $optionalKeys = [
    ];

    $givenConfigKeys = array_keys($configuration);

    $missingKeys = array_diff($mandatoryKeys, $givenConfigKeys);
    if (count($missingKeys) > 0) {
      $message = sprintf("Missing configuration parameters '%s'.", implode(', ', $missingKeys));
      throw new \Exception($message);
    }

    $extraKeys = array_diff($givenConfigKeys, array_merge($optionalKeys, $mandatoryKeys));
    if (count($extraKeys) > 0) {
      $message = sprintf("Unknown configuration parameters '%'.", implode(', ', $extraKeys));
      throw new Exception($message);
    }

    return $configuration;
  }

  /**
   * Reset the manager
   *
   * @param type $algorithm
   */
  protected function reset($algorithm)
  {
    $config = [
        'algorithm' => $algorithm,
        'num-first-iterations'  => $this->get('num_first_iterations'),
        'num-second-iterations' => $this->get('num_second_iterations'),
        'num-final-iterations'  => $this->get('num_final_iterations')
    ];

    $this->manager = new Manager(new Hash);
    $this->manager->config($config);
    $this->manager->ttl($this->get('ttl'));
  }
}
