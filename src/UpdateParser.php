<?php

namespace Drupal\security_advisories;

class UpdateParser
{
  public function __construct()
  {
    module_load_include('inc', 'update', 'update.compare');

    $available = update_get_available();

    $projects = update_calculate_project_data($available);
    foreach($projects as $project)
    {

    }
  }
}