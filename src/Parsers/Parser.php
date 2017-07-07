<?php

namespace Drupal\security_advisories\Parsers;

use Drupal\security_advisories\Advisory;

class Parser
{
  const MULTIPLE_VULNERABILITIES_IDENTIFIER = "Multiple vulnerabilities";

  var $title;
  var $language;

  var $items = [];

  public function __construct($file)
  {
    $content = $this->loadXMLFile($file);
    $xml = new \SimpleXMLElement($content);

    $this->title = $xml->channel->title;
    $this->language = $xml->channel->language;
    foreach($xml->channel->item as $item)
    {
      /**
       * @author  lindelee@sph.com.sg
       * @date    06 Jul 2017
       *
       * Determine if this advisory is for multiple vulnerabilities.
       * If there are multiple vulnerabilities, do a separate identification.
       */

//      if(preg_match("/" . self::MULTIPLE_VULNERABILITIES_IDENTIFIER . "/i", $item->title))
//      {
//        $this->multipleVulnerabilities($item);
//      }
//      else
//      {
        $advisory = new Advisory($item);
        $this->items[] = $advisory;
//      }
    }
  }

  private function loadXMLFile($file)
  {
    $context  = stream_context_create(array('http' => array('header' => 'Accept: application/xml')));
    $content = file_get_contents($file, FALSE, $context);

    return $content;
  }

  /**
   * @author  lindelee@sph.com.sg
   * @date    07 Jul 2017
   *
   * If there is more than one vulnerability being identified, this will try
   * to extract those vulnerabilities.
   *
   * Usually this is only for Drupal Core vulnerabilities. It seems illogical
   * for contributed modules to aggregate the vulnerabilities.
   */

//  private function multipleVulnerabilities($item)
//  {
//
//  }
}