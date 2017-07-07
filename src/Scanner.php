<?php

namespace Drupal\security_advisories;

class Scanner
{
  const UNRELIABLE_DETERMINE_MESSAGE = "<ul><li>Could not reliably determine the vulnerable version. Requires manual evaluation.</li></ul>";
  const UNDEFINED_PROJECT = "Undefined";

  const MULTIPLE_VULNERABILITIES = "Multiple vulnerabilities";

  var $CORE;
  var $list = [];
  var $undetermined = [];

  public function __construct()
  {
    $this->CORE = substr(VERSION, 0, 2);
    new \Drupal\security_advisories\Updater();

    /**
     * @author  lindelee@sph.com.sg
     * @date    07 Jul 2017
     *
     * Run the updater before scanning.
     */

    $contrib = [];
    $drupal = [];
    $undefined = [];

    $query = db_query("SELECT * FROM {" . SecurityAdvisoriesContract::TABLE_NAME . "}");
    foreach($query as $advisory)
    {
      $module = $this->retrieveModule($advisory);
      if($module)
      {
        if(!$this->verifyVulnerableVersion($module, $advisory))
        {
          $module = new Module($module, $advisory);
          $contrib[$module->risk][] = $module;
        }
      }
      else if($advisory->project == "drupal")
      {
        /**
         * @author  lindelee@sph.com.sg
         * @date    07 Jul 2017
         *
         * If the advisory is for the Drupal core, collate them and cross check.
         */

        $drupal[] = $advisory;
      }
      else if ($advisory->project == "")
      {
        /**
         * @author  lindelee@sph.com.sg
         * @date    07 Jul 2017
         *
         * If the advisory cannot be identified, require manual verification.
         */

        $module = [
          'name'            => self::UNDEFINED_PROJECT,
          'description'     => "Could not be reliably determined"
        ];

        $advisory->project = self::UNDEFINED_PROJECT;

        $module = new Module($module, $advisory);
        $undefined[$module->risk][] = $module;
      }
    }

    $core = $this->drupalCoreVulnerabilityChecks($drupal);

    /**
     * @author  lindelee@sph.com.sg
     * @date    07 Jul 2017
     *
     * Sort by date, then by risk.
     */
    $this->list = array_merge($this->list, $this->sortModules($contrib));
    $this->list = array_merge($this->list, $this->sortModules($core));
    $this->undetermined = $this->sortModules($undefined);
  }

  private function sortModules($list)
  {
    foreach($list as $risk => $module)
    {
      usort($list[$risk], [
        $this,
        'sortModulesByDate'
      ]);
    }

    ksort($list);

    $result = [];
    foreach($list as $risk => $module)
    {
      $result = array_merge($result, $list[$risk]);
    }

    return $result;
  }

  private function sortModulesByDate($a, $b)
  {
    return $b->advisory_date - $a->advisory_date;
  }

  /**
   * @author  lindelee@sph.com.sg
   * @date    06 Jul 2017
   *
   * Since the module_list function doesn't return the information about the
   * module, manually pull it using query.
   *
   * This is not in the defined types in the EntityFieldQuery, so I will build
   * the SQL queries manually.
   *
   * Lists all the compromised modules that require patching.
   */

  private function retrieveModule($advisory)
  {
    $result = db_query("SELECT name, filename, info FROM {system} WHERE name = :name ORDER BY weight ASC, filename ASC",
    [
      ':name'       => $advisory->project
    ]);

    if($result->rowCount() > 0)
    {
      $module = $result->fetchObject();
      if (file_exists($module->filename))
      {
        $info = unserialize($module->info);

        drupal_get_filename('module', $module->name, $module->filename);

        /**
         * @author  lindelee@sph.com.sg
         * @date    22 Jun 2017
         *
         * Set human readable date to mtime (installation date).
         */
        return [
          'namespace' => $module->name,
          'file' => $module->filename,
          'name' => $info['name'],
          'description' => $info['description'],
          'version' => $info['version'],
          'core' => $info['core'],
          'mtime' => $info['mtime'],
          'install_date' => date("d M Y, h:iA", $info['mtime'])
        ];
      }
    }

    return FALSE;
  }

  private function verifyVulnerableVersion(&$module, &$advisory)
  {
    $installed = $module['version'];
    $required = $advisory->version;

    $control = $this->validateVersions($installed, $required);

    if(!$control['vc'])
    {
      $module['description'] = "<div>" . $module['description'] . "</div>" . self::UNRELIABLE_DETERMINE_MESSAGE;
    }

    return $control['latest'];
  }

  private function drupalCoreVulnerabilityChecks($drupal)
  {
    $core = VERSION;
    $core = "7.43"; // fake version

    $list = [];

    $_module = [
      'name'            => "core",
      'description'     => "Drupal core.",
      'version'         => $core
    ];

    foreach($drupal as $advisory)
    {
      $required = $advisory->version;
      $control = $this->validateVersions($core, $required);

      if (!$control['vc'])
      {
        $_module['description'] = "<div>" . $_module['description'] . "</div>" . self::UNRELIABLE_DETERMINE_MESSAGE;
      }

      if(!$control['latest'])
      {
        $module = new Module($_module, $advisory);
        $list[$module->risk][] = $module;
      }
    }

    return $list;
  }

  private function validateVersions($installed, $required)
  {
    $latest = FALSE;

    $installed = str_replace($this->CORE . "x-", "", $installed);
    $required = str_replace($this->CORE . "x-", "", $required);

    $installed = preg_replace("/[^0-9\.]/", "", $installed);
    $required = preg_replace("/[^0-9\.]/", "", $required);

    $installed = explode(".", $installed);
    $required = explode(".", $required);

    /**
     * @author  lindelee@sph.com.sg
     * @date    07 Jul 2017
     *
     * If it cannot be reliably determined, return the fix for manual vetting.
     */

    $vc = FALSE;
    foreach($required as $key => $control)
    {
      if($control !== "")
      {
        if ($installed[$key] !== "")
        {
          $vc = TRUE;
          if ($control < $installed[$key])
          {
            $latest = TRUE;
          }
        }
      }
    }

    if($required === $installed)
    {
      $latest = TRUE;
    }

    return [
      'vc'          => $vc,
      'latest'      => $latest
    ];
  }
}