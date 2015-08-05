<?php

namespace SoftRog\StatelessAuth;

class ParameterBag
{
  /** @var array */
  protected $parameters;

  public function __construct($parameters=[])
  {
    if (!is_array($parameters)) {
      throw new \InvalidArgumentException('Parameters has to be an array.');
    }

    $this->parameters = $parameters;
  }

  /**
   * Add a parameter
   *
   * @param string $key
   * @param mixed $value
   */
  public function add($key, $value)
  {
    $this->parameters[$key] = $value;
  }

  /**
   * Check if the $key exists in the parameter
   *
   * @param string $key
   * @return mixed
   */
  public function has($key)
  {
    return array_key_exists($key, $this->parameters);
  }

  /**
   * Get the parameter $key
   *
   * @param string $key
   * @return mixed
   */
  public function get($key)
  {
    if ($this->has($key)) {
      return $this->parameters[$key];
    }

    return false;
  }

}
