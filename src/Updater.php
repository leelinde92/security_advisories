<?php

namespace Drupal\security_advisories;

class Updater
{
  public function __construct()
  {
    drupal_set_message("Updating securities list.");

    $core = new \Drupal\security_advisories\Parsers\CoreParser();
    $contrib = new \Drupal\security_advisories\Parsers\ContribParser();

    foreach($core->items as $advisory)
    {
      $this->processAdvisory($advisory);
    }

    foreach($contrib->items as $advisory)
    {
      $this->processAdvisory($advisory);
    }

    drupal_set_message("Updated securities list.");
  }

  private function processAdvisory($advisory)
  {
    if($advisory->relevance)
    {
      $query = db_query("SELECT * FROM {" . SecurityAdvisoriesContract::TABLE_NAME . "} WHERE advisoryId = :advisoryid LIMIT 1", [
        ':advisoryid' => $advisory->advisoryId
      ]);

      if ($query->rowCount() <= 0)
      {
        if (!empty($advisory->advisoryId))
        {
          db_insert(SecurityAdvisoriesContract::TABLE_NAME)
            ->fields([
              'advisoryId' => $advisory->advisoryId,
              'link' => $advisory->link,
              'project' => $advisory->project,
              'description' => $advisory->description,
              'version' => $advisory->version,
              'risk' => $advisory->risk,
              'solution' => $advisory->solution,
              'date' => $advisory->date
            ])
            ->execute();
        }
      }
    }
  }
}