<?php

namespace Drupal\security_advisories\Parsers;

use Drupal\security_advisories\Advisory;
use Drupal\security_advisories\Notifier;

class Parser
{
  const MULTIPLE_VULNERABILITIES_IDENTIFIER = "Multiple vulnerabilities";
  const CERTIFICATE_PATH = "/res/certs/drupal-security.crt";

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

        $advisory = new Advisory($item);
        $this->items[] = $advisory;
    }
  }

  private function loadXMLFile($file)
  {
    $curl = curl_init();
    curl_setopt_array($curl, [
      CURLOPT_URL             => $file,
      CURLOPT_HEADER          => 0,
      CURLOPT_RETURNTRANSFER  => TRUE,
      CURLOPT_SSL_VERIFYPEER  => TRUE,
      CURLOPT_SSL_VERIFYHOST  => 2,
      CURLOPT_CAINFO          => realpath(drupal_get_path("module", Notifier::MODULE) . self::CERTIFICATE_PATH)
    ]);

    $data = curl_exec($curl);
    if(curl_error($curl))
    {
      drupal_set_message("An error occured while trying to crawl the advisory: " . curl_error($curl), "error");
    }

    curl_close($curl);

    return $data;
  }
}