<?php

namespace Drupal\security_advisories;

class Notifier
{
  /**
   * @author  lindelee@sph.com.sg
   * @date    07 Jul 2017
   *
   * Sends a list of the most recent updated advisories.
   * Will always include the list of identified security patches required.
   */

  const MODULE = "security_advisories";
  const SECURITIES_ADVISORIES_VARIABLE = "security_advisories_update";
  const MAIL_CSS_PATH = "/res/css/mail.css";
  const RECIPIENTS = [
    'lindelee@sph.com.sg'       => "Lee Lin De"
  ];

  private $site;

  public function __construct()
  {
    $this->site = variable_get('site_name');
  }

  public function send()
  {
    $mailer = new \DrupalPHPMailer();
    foreach(self::RECIPIENTS as $recipient => $name)
    {
      $mailer->addAddress($recipient, $name);
    }

    $mailer->Subject = "[" . variable_get('site_name') . "] Security Advisory Notification";
    $mailer->Body = $this->html();
    $mailer->isHTML(TRUE);

    $mailer->send();

    drupal_set_message("Sent an e-mail to all involved recipients.");
  }

  private function html()
  {
    global $base_url;

    $table = Renderer::mailTable();

    $body = "<html>";
    $body .= "<head><style>" . file_get_contents(drupal_get_path("module", self::MODULE) . self::MAIL_CSS_PATH) . "</style></head>";
    $body .= "<body>";
    $body .= "<div>" . date("j M Y", time()) .  " update for a list of vulnerabilities on modules installed in " . $this->site . "</div>";
    $body .= "<div>For a list of comprehensive summary, <a href=\"" . $base_url . "/admin/reports/vulnerabilities/list\">visit your site's vulnerabilities listing</a>.</div>";
    $body .= render($table);
    $body .= "</body>";
    $body .= "</html>";

    return $body;
  }
}