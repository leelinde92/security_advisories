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
    'Lee Lin De'          => "lindelee@sph.com.sg"
  ];

  private $site;

  public function __construct()
  {
    $this->site = variable_get('site_name');
  }

  public function send()
  {
    if(phpmailer_enabled())
    {
      $mailer = new \DrupalPHPMailer();
      foreach (self::RECIPIENTS as $recipient => $name)
      {
        $mailer->addAddress($recipient, $name);
      }

      $mailer->Subject = "[" . $this->site . "] Security Advisory Notification";
      $mailer->Body = $this->html();
      $mailer->isHTML(TRUE);

      $mailer->send();
    }
    else
    {
      $header_to = [];
      foreach (self::RECIPIENTS as $name => $recipient)
      {
        $header_to[] = $name . "<" . $recipient . ">";
      }

      $header_to = implode(", ", $header_to);
      $to = implode(",", self::RECIPIENTS);

      $headers = [];
      $headers[] = 'MIME-Version: 1.0';
      $headers[] = 'Content-type: text/html; charset=iso-8859-1';
      $headers[] = "To: " . $header_to;

      $subject = "[" . $this->site . "] Security Advisory Notification";
      $message = $this->html();

      mail($to, $subject, $message, implode("\r\n", $headers));
    }

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