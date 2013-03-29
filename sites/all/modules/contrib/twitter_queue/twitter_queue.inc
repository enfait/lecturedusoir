<?php

/**
 * @file
 * @todo documentation
 */

/**
 * @todo documentation
 *
 * @param int $nid
 * @param bool $goto
 */
function twitter_queue_send($nid, $goto = TRUE) {
  module_load_include('php', 'twitter_queue', 'class/TwitterQueue');
  $test = !variable_get('twitter_queue_test', 0) ? '' : '_test';

  $settings = array(
    'consumer_key'    => variable_get('twitter_queue_consumer_key' . $test, ''),
    'consumer_secret' => variable_get('twitter_queue_consumer_secret' . $test, ''),
    'user_token'      => variable_get('twitter_queue_user_token' . $test, ''),
    'user_secret'     => variable_get('twitter_queue_user_secret' . $test, ''),
  );

  $twitter_queue = new TwitterQueue($settings);

  $status = db_select('twitter_queue', 'tq')
  ->fields('tq', array('text_status'))
  ->condition('nid', $nid)
  ->execute()
  ->fetchField();

  $request = $twitter_queue->request('post', $twitter_queue->url('1/statuses/update'), array('status' => $status));

  if ($request == 200) {
    $message = "The tweet id: @id was successfully sended." . PHP_EOL;
    $message .= "The status sended was: @status";
    watchdog('twitter_queue', $message, array('@id' => $nid, '@status' => $status));

    db_delete('twitter_queue')
    ->condition('nid', $nid)
    ->execute();

    if (is_numeric($nid)) {
      db_update('twitter_queue_status')
      ->fields(array(
        'status' => 0,
      ))
      ->execute();

    }

    // we want some redirect?
    if ($goto) {
      drupal_goto('admin/structure/twitter-queue');
    }
    return TRUE;
  }
  else {
    return FALSE;
  }
}

/**
 * @todo documentation
 */
function twitter_queue_send_live($text) {
  module_load_include('php', 'twitter_queue', 'class/TwitterQueue');
  $test = !variable_get('twitter_queue_test', 0) ? '' : '_test';

  $settings = array(
    'consumer_key'    => variable_get('twitter_queue_consumer_key' . $test, ''),
    'consumer_secret' => variable_get('twitter_queue_consumer_secret' . $test, ''),
    'user_token'      => variable_get('twitter_queue_user_token' . $test, ''),
    'user_secret'     => variable_get('twitter_queue_user_secret' . $test, ''),
  );

  $twitter_queue = new TwitterQueue($settings);

  $code = $twitter_queue->request('POST', $twitter_queue->url('1/statuses/update'), array('status' => $text));

  if ($code == 200) {
    drupal_set_message(t('Tweet sended successfully'));
  }
  else {
    drupal_set_message(t('Some error accour, maybe this tweet was already sended.'), 'error');
  }

  drupal_goto('admin/structure/twitter-queue');
}

/**
 * Internal function to handle the insert and update process of a node.
 *
 * @param  obj $node node object
 * @return void
 */
function _twitter_queue_ins_upd($node) {
  $array_types = variable_get('twitter_queue_types', array());
  $holder = "twitter_queue_{$node->type}_status";

  if (in_array($node->type, $array_types) && $node->{$holder}) {

    db_merge('twitter_queue')
    ->key(array('nid' =>$node->nid))
    ->fields(array(
        'weight'      => -20,
        'node_status' => $node->status,
        'text_status' => $node->title,
      ))
    ->updateFields(array(
        'node_status' => $node->status,
        'text_status' => $node->title,
      ))
    ->execute();

    db_merge('twitter_queue_status')
    ->key(array('nid' => $node->nid))
    ->fields(array(
        'status' => $node->{$holder}
      ))
    ->execute();

  }
}
