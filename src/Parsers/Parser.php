<?php

namespace Drupal\security_advisories\Parsers;

use Drupal\security_advisories\Advisory;

class Parser
{
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
       * If there are multiple vulnerabilities, do a separate identification.
       */

      $advisory = new Advisory($item);
      $this->items[] = $advisory;
    }
  }

  private function loadXMLFile($file)
  {
    $context  = stream_context_create(array('http' => array('header' => 'Accept: application/xml')));
    $content = file_get_contents($file, FALSE, $context);

    return $content;
  }
}