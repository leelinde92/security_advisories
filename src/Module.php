<?php

namespace Drupal\security_advisories;

class Module
{
  var $project;
  var $link;
  var $file;
  var $version;
  var $minimum;
  var $risk;
  var $risk_description;
  var $vulnerability_description;
  var $description;
  var $solution;
  var $install_date;
  var $advisory_date;

  public function __construct($module, $advisory)
  {
    $this->advisoryId = $advisory->advisoryId;
    $this->project = $advisory->project;
    $this->minimum = str_replace("7.x-", "", $advisory->version);
    $this->risk = $advisory->risk;
    $this->vulnerability_description = $advisory->description;
    $this->solution = $advisory->solution;
    $this->advisory_date = $advisory->date;
    $this->risk_description = Advisory::RISK_ASSESSMENTS[$advisory->risk];
    $this->link = $advisory->link;

    $this->version = str_replace("7.x-", "", $module['version']);
    $this->description = $module['description'];
    $this->install_date = $module['mtime'];
    $this->file = $module['file'];
  }
}