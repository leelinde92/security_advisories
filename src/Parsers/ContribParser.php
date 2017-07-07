<?php

namespace Drupal\security_advisories\Parsers;

class ContribParser extends Parser
{
  const FEED = "https://www.drupal.org/security/contrib/rss.xml";

  /**
   * @author  lindelee@sph.com.sg
   * @date    05 Jul 2017
   *
   * Each item always has a ul with the following format:
   * - Advisory ID
   * - Project
   * - Version
   * - Date
   * - Security Risk
   * - Vulnerability
   */

  public function __construct()
  {
    parent::__construct(self::FEED);
  }
}