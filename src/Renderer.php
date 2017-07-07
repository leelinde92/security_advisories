<?php

namespace Drupal\security_advisories;

class Renderer
{
  const NO_VULNERABILITIES_MESSAGE = "<div class=\"center\">Impending doom is missing.</div>";

  const DATE_FORMAT = "j M Y";
  const ADVISORIES_CORE_LINK = "https://www.drupal.org/";
  const ADVISORIES_CONTRIB_LINK = "https://www.drupal.org/node/";

  const HEADINGS = [
    'Advisory ID',
    'Project',
    'Description',
    'Vulnerability',
    'Current version',
    'Minimum',
    'Risk',
    'Solution',
    'Installed on',
    'Advisory released'
  ];

  public static function infoTable()
  {
    $headers = self::HEADINGS;

    $scanner = new \Drupal\security_advisories\Scanner();

    $rows = [];
    foreach($scanner->list as $module)
    {
      $install_date = '';
      if(!empty($module->install_date))
      {
        $install_date = date(self::DATE_FORMAT, $module->install_date);
      }

      $rows[] = [
        l($module->advisoryId, $module->link),
        $module->project,
        $module->description,
        $module->vulnerability_description,
        [
          'data' => $module->version,
          'align' => "center"
        ],
        [
          'data' => $module->minimum,
          'align' => "center"
        ],
        $module->risk_description,
        $module->solution,
        $install_date,
        date(self::DATE_FORMAT, $module->advisory_date)
      ];
    }

    return [
      '#theme'    => 'table',
      '#header'   => $headers,
      '#rows'     => $rows,
      '#empty'    => self::NO_VULNERABILITIES_MESSAGE
    ];
  }
}