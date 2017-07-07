<?php

namespace Drupal\security_advisories;

class Notifier
{
  const MODULE = "security_advisories";
  const RECIPIENTS = [
    'lindelee@sph.com.sg'
  ];

  private $mail;

  public function __construct()
  {
    $table = Renderer::infoTable();
    $table = render($table);

    $this->mail .= $table;
  }

  public function mail()
  {
    drupal_mail(self::MODULE, 'notice', 'lindelee@sph.com.sg', '', [

    ]);
  }
}