<?php

namespace SoftRog\StatelessAuth;

class ConfigurationProcessor
{
  /** @var array */
  protected $mandatoryKeys = [
      'algorithm',
      'signed_headers',
      'num_first_iterations',
      'num_second_iterations',
      'num_final_iterations',
  ];

  /** @var array */
  protected $optionalKeys = [
      'id',
      'key',
      'ttl',
  ];

  /**
   * Process the given configuration checking if the needed settings are valid
   *
   * @param array $configuration
   * @return array
   * @throws \Exception
   */
  public function process(array $configuration)
  {
    $givenConfigKeys = array_keys($configuration);

    $missingKeys = array_diff($this->mandatoryKeys, $givenConfigKeys);
    if (count($missingKeys) > 0) {
      $message = sprintf("Missing configuration parameters '%s'.", implode(', ', $missingKeys));
      throw new \Exception($message);
    }

    $extraKeys = array_diff($givenConfigKeys, array_merge($this->optionalKeys, $this->mandatoryKeys));
    if (count($extraKeys) > 0) {
      $message = sprintf("Unknown configuration parameters '%s'.", implode(', ', $extraKeys));
      throw new \Exception($message);
    }

    return $configuration;
  }

}
