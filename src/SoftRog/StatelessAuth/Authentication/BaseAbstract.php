<?php

namespace SoftRog\StatelessAuth\Authentication;

use Mardy\Hmac\Manager;
use Mardy\Hmac\Adapters\Hash;
use SoftRog\StatelessAuth\ParameterBag;
use SoftRog\StatelessAuth\ConfigurationProcessor;

abstract class BaseAbstract
{

  /** @var array */
  protected $configuration;

  /** @var Manager */
  protected $manager;

  /**
   * Build up an object with the given configuration
   *
   * @param array $configuration
   */
  public function __construct(array $configuration)
  {
    $configurationProcessor = new ConfigurationProcessor();
    $this->configuration = new ParameterBag($configurationProcessor->process($configuration));
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
        'num-first-iterations' => $this->configuration->get('num_first_iterations'),
        'num-second-iterations' => $this->configuration->get('num_second_iterations'),
        'num-final-iterations' => $this->configuration->get('num_final_iterations')
    ];

    $this->manager = new Manager(new Hash);
    $this->manager->config($config);
    $this->manager->ttl($this->configuration->get('ttl'));
  }

}
