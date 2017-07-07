<?php

/**
 * Implements drush_hook_command
 */
function sph_security_advisories_command(){
  $items['update-security-advisories'] = array(
    'callback'    => 'drush_advisories_update',
    'description' => t('Updates list of advisories in the database.'),
    'aliases'     => [
      'security-update'
    ]
  );

  $items['notify-vulnerabilities'] = array(
    'callback'    => 'drush_notify_vulnerabilities',
    'description' => t('Notifies declared recipients about the vulnerabilities.'),
    'aliases'     => [
      'security-notify'
    ]
  );

  return $items;
}

function drush_advisories_update(){
  new \Drupal\security_advisories\Updater();
}

function drush_notify_vulnerabilities(){
  $notifier = new \Drupal\security_advisories\Notifier();

}