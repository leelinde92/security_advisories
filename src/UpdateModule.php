<?php

class UpdateModule extends \Drupal\security_advisories\Module
{
  public function __construct($project, $release)
  {
    $module = [];
    $advisory = [];

    parent::__construct($module, $advisory);
  }
}