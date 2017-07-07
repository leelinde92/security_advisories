<?php

namespace Drupal\security_advisories;

class Advisory
{
  const ADVISORY_PATTERN = "/\<ul\>\<li\>Advisory ID:(.*?)\<\/li\>(.*?)\<\/ul\>/si";
  const STRIP_LIST = "/\<ul\>(.*?)\<\/ul\>/";
  const STRIP_ITEM = "/\<li\>(.*?)\<\/li\>/";
  const PROJECT_PATTERN = "/\"http(:?s)\:\/\/" . self::PROJECT_LINK . "(.*?)\"/";
  const VERSION_PATTERN = "/[0-9]{1}\.(?:[0-9]{1,}|x{1})(?:(\.|\-)([0-9]+|x)(\.[0-9]+)?)?/";
  const SOLUTION_VERSION_PATTERN = "/(?:\<a(.*?))[0-9]{1}\.(?:[0-9]{1,}|x{1})(?:(\.|\-)([0-9]+|x)(\.[0-9]+)?)?(?:\<\/a\>)/";
  const SOLUTION_PATTERN = "/(?:\<h[0-9]{1}\>Solution(s)?\<\/h[0-9]{1}\>(.*?)(\<ul\>|\<ol\>))(.*?)(?:(\<\/ul\>|\<\/ol\>))/s";
  const LINK_TEXT_PATTERN = "/^(.*?)\<a(.*?)\>(.*?)\<\/a\>(.*?)$/";
  const DRUPAL_CORE_PATTERN = "/^(?!Drupal\s+(core)?\s+)[0-9]{1}\.[0-9]{1,}(\.[0-9]{1,})?+/";
  const CORE_VERSION_PATTERN = "/^(.*?)(?<=[0-9]{1}\.)/";

  const PROJECT_LINK = "www.drupal.org\/project\/";

  const FIELD_ADVISORY_ID = "Advisory ID";
  const FIELD_PROJECT     = "Project";
  const FIELD_VERSION     = "Version";
  const FIELD_DATE        = "Date";
  const FIELD_RISK        = "Security risk";
  const FIELD_DESCRIPTION = "Vulnerability";

  const HIGHLY_CRITICAL     = 1;
  const MODERATELY_CRITICAL = 2;
  const CRITICAL            = 3;
  const LESS_CRITICAL       = 4;
  const NOT_CRITICAL        = 5;

  const RISK_ASSESSMENTS = [
    self::HIGHLY_CRITICAL     => "Highly Critical",
    self::MODERATELY_CRITICAL => "Moderately Critical",
    self::LESS_CRITICAL       => "Less Critical",
    self::NOT_CRITICAL        => "Not Critical",
    self::CRITICAL            => "Critical"
  ];

  const VERSIONS = [
    '7.x'         => "Drupal 7",
    '8.x'         => "Drupal 8"
  ];

  var $advisoryId;
  var $link;
  var $project;
  var $description;
  var $version;
  var $risk = NULL;
  var $solution;
  var $date;

  var $relevance = FALSE;
  var $core_version = [];

  public function __construct($item)
  {
    $this->link = $item->link;
    $description = $item->description;
    $core = substr(VERSION,0,2);

    /**
     * @author  lindelee@sph.com.sg
     * @date    05 Jul 2017
     *
     * Match the ul with advisory ID
     */

    $matches = [];
    preg_match(self::ADVISORY_PATTERN, $description, $matches);
    if(!empty($matches[0]))
    {
      $advisory = $matches[0];
      $advisory = preg_replace(self::STRIP_LIST, "$1", $advisory);
      $advisory = preg_replace(self::STRIP_ITEM, "$1 | ", $advisory);
      $advisory = strip_tags($advisory, "<a>");

      $info = explode("|", $advisory);

      foreach($info as $field)
      {
        $field = trim($field);
        $data = explode(":", $field);

        $field_name = array_shift($data);
        $field_name = trim($field_name);

        $content = implode(":", $data);
        switch ($field_name)
        {
          case self::FIELD_ADVISORY_ID:
            $this->advisoryId = trim($content);
            break;
          case self::FIELD_PROJECT:
            $content = trim($content);
            $project_matches = [];
            preg_match(self::PROJECT_PATTERN, $content, $project_matches);
            $this->project = array_pop($project_matches);
            break;
          case self::FIELD_VERSION:
            $versions = [];
            preg_match_all(self::VERSION_PATTERN, $content, $versions);
            foreach($versions[0] as $version)
            {
              $this->core_version[] = $version;
            }

            break;
          case self::FIELD_DATE:
            $this->date = strtotime(trim($content));
            break;
          case self::FIELD_RISK:
            $risk_line = trim($content);
            foreach(self::RISK_ASSESSMENTS as $key => $risk)
            {
              if($this->risk === NULL)
              {
                if (strpos(strtoupper($risk_line), strtoupper($risk)) !== FALSE)
                {
                  $this->risk = $key;
                }
              }
            }
            break;
          case self::FIELD_DESCRIPTION:
            $this->description = trim($content);
            break;
        }
      }
    }

    /**
     * @author  lindelee@sph.com.sg
     * @date    06 Jul 2017
     *
     * Match the relevancy of the advisory to the Drupal core version.
     * If the core version can't be determined, then it will mark as relevant
     * anyway.
     */
    if(!empty($this->core_version))
    {
      foreach ($this->core_version as $version)
      {
        if (preg_match("/^" . preg_quote($core, "/") . "/", $version))
        {
          $this->relevance = TRUE;
        }
      }
    }
    else
    {
      $this->relevance = TRUE;
    }

    /**
     * @author  lindelee@sph.com.sg
     * @date    06 Jul 2017
     *
     * Sift for the latest version required for the module from the solution
     * section.
     *
     * Store the solution, and identify the strongest version if available.
     */

    $contrib = FALSE;
    if(!empty($this->project) && $this->project != "drupal")
    {
      $contrib = TRUE;
    }

    $solution = [];
    preg_match(self::SOLUTION_PATTERN, $description, $solution);
    if(!empty($solution[0]))
    {
      $this->solution = $solution[0];
      $this->solution = preg_replace("/<h[0-9]{1}\>Solution(s)?\<\/h[0-9]{1}\>/s", "", $this->solution);

      if($contrib)
      {
        $versions = [];
        preg_match_all(self::SOLUTION_VERSION_PATTERN, $this->solution, $versions);

        if(!empty($versions[0]))
        {
          foreach ($versions[0] as $version)
          {
            $link_text = preg_replace(self::LINK_TEXT_PATTERN, "$3", $version);
            preg_match(self::VERSION_PATTERN, $link_text, $module_versions);
            if (!empty($module_versions))
            {
              foreach($module_versions as $module_version)
              {
                if (preg_match("/^(?!Drupal\ )[0-9]{1}\.x\-/", $module_version))
                {
                  if (preg_match("/^" . preg_quote($core, "/") . "/", $module_version))
                  {
                    $this->version = $module_version;
                  }
                }
              }
            }
          }
        }
        else
        {
          preg_match_all(self::VERSION_PATTERN, $this->solution, $module_versions);
          if (!empty($module_versions[0]))
          {
            foreach($module_versions[0] as $version)
            {
              if (preg_match("/(?!Drupal )[0-9]{1}\.x-/", $version))
              {
                $this->version = $version;
              }
            }
          }
        }
      }
      else
      {
        $versions = [];
        preg_match_all(self::SOLUTION_VERSION_PATTERN, $this->solution, $versions);

        if(!empty($versions[0]))
        {
          foreach ($versions[0] as $version)
          {
            $link_text = preg_replace(self::LINK_TEXT_PATTERN, "$3", $version);
            preg_match(self::VERSION_PATTERN, $link_text, $module_versions);
            if (!empty($module_versions))
            {
              foreach($module_versions as $module_version)
              {
                if (preg_match(self::DRUPAL_CORE_PATTERN, $module_version))
                {
                  if (preg_match("/^" . preg_quote($core, "/") . "/", $module_version))
                  {
                    $this->version = $module_version;
                  }
                }
              }
            }
          }
        }
        else
        {
          preg_match_all(self::VERSION_PATTERN, $this->solution, $module_versions);
          if (!empty($module_versions[0]))
          {
            foreach($module_versions[0] as $version)
            {
              if (preg_match(self::DRUPAL_CORE_PATTERN, $version))
              {
                if (preg_match("/^" . preg_quote($core, "/") . "/", $version))
                {
                  $this->version = $version;
                }
              }
            }
          }
        }
      }
      /**
       * @author  lindelee@sph.com.sg
       * @date    06 Jul 2017
       *
       * If the module is Drupal core, add the version that is minimum.
       */


    }
  }
}