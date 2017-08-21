<?php

/*

  Plugin Name: JSON API Rest

  Description: A simple Rest extension for the JSON API to use WP as a (VERY) simple backend

  Version: 1.0

  Author: Yoni Kalangan

  License: GPLv3

 */

define('JAU_VERSION', '1.0');

include_once( ABSPATH . 'wp-admin/includes/plugin.php' );

define('JSON_API_REST_HOME', dirname(__FILE__));



if (!is_plugin_active('json-api/json-api.php')) {

    add_action('admin_notices', 'pim_draw_notice_json_api_no_ssl');

    return;

}



add_filter('json_api_controllers', 'pimJsonRestApiController');

add_filter('json_api_rest_controller_path', 'setRestControllerPath');

add_action('init', 'json_api_rest_checkAuthCookie', 100);

load_plugin_textdomain('json-api-rest', false, basename(dirname(__FILE__)) . '/languages');



function pim_draw_notice_json_api_no_ssl() {
    echo '<div id="message" class="error fade"><p style="line-height: 150%">';
    _e('<strong>JSON API Rest</strong></a> requires the JSON API plugin to be activated. Please <a href="wordpress.org/plugins/json-api/‎">install / activate JSON API</a> first.', 'json-api-rest');
    echo '</p></div>';
}



function pimJsonRestApiController($aControllers) {
    $aControllers[] = 'Rest';
    return $aControllers;
}



function setRestControllerPath($sDefaultPath) {
    return dirname(__FILE__) . '/controllers/Rest.php';
}

function json_api_rest_checkAuthCookie($sDefaultPath) {
    global $json_api;

    if ($json_api->query->cookie) {
      $user_id = wp_validate_auth_cookie($json_api->query->cookie, 'logged_in');
      if ($user_id) {
        $user = get_userdata($user_id);

        wp_set_current_user($user->ID, $user->user_login);
      }
    }
}