<?php

namespace Drupal\security_advisories\Parsers;

class CoreParser extends Parser
{
  const FEED = "https://www.drupal.org/security/rss.xml";

  public function __construct()
  {
    parent::__construct(self::FEED);
  }
}