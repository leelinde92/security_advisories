<?php

namespace Drupal\security_advisories;

class Renderer
{
  const NO_VULNERABILITIES_MESSAGE = "<div class=\"center\">Impending doom is missing.</div>";
  const NO_UNDETERMINED_MESSAGE = "<div class=\"center\">All vulnerabilities were identifiable.</div>";

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
    'Advisory released'
  ];

  const MAIL_HEADINGS = [
    'Advisory ID',
    'Project',
    'Vulnerability',
    'Current version',
    'Minimum',
    'Risk',
    'Advisory released'
  ];

  public static function infoTable()
  {
    $headers = self::HEADINGS;

    $scanner = new Scanner();

    $list_rows = self::convertListToRows($scanner->list);
    $undetermined_rows = self::convertListToRows($scanner->undetermined);

    return [
      'list'            => [
        '#theme'          => 'table',
        '#header'         => $headers,
        '#rows'           => $list_rows,
        '#empty'          => self::NO_VULNERABILITIES_MESSAGE
      ],
      'undetermined'    => [
        '#theme'          => 'table',
        '#header'         => $headers,
        '#rows'           => $undetermined_rows,
        '#empty'          => self::NO_UNDETERMINED_MESSAGE
      ]
    ];
  }

  public static function mailTable()
  {
    $headers = self::MAIL_HEADINGS;

    $scanner = new Scanner();

    $list_rows = self::convertMailListToRows($scanner->list);
    $undetermined_rows = self::convertMailListToRows($scanner->undetermined);

    return [
      'list'            => [
        '#theme'          => 'table',
        '#header'         => $headers,
        '#rows'           => $list_rows,
        '#empty'          => self::NO_VULNERABILITIES_MESSAGE
      ],
      'undetermined'    => [
        '#theme'          => 'table',
        '#header'         => $headers,
        '#rows'           => $undetermined_rows,
        '#empty'          => self::NO_UNDETERMINED_MESSAGE
      ]
    ];
  }

  private static function convertListToRows($list)
  {
    $rows = [];
    foreach($list as $module)
    {

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
        date(self::DATE_FORMAT, $module->advisory_date)
      ];
    }

    return $rows;
  }

  private static function convertMailListToRows($list)
  {
    $rows = [];
    foreach($list as $module)
    {

      $rows[] = [
        l($module->advisoryId, $module->link),
        $module->project,
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
        date(self::DATE_FORMAT, $module->advisory_date)
      ];
    }

    return $rows;
  }
}