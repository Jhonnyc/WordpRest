<?php
/**
 * Created by IntelliJ IDEA.
 * User: Yoni
 * Date: 20/08/2017
 * Time: 22:19
 */
define('KB', 1024);
define('MB', 1048576);
define('GB', 1073741824);
define('TB', 1099511627776);
class JSON_API_Rest_Controller {

    var $SECURE = FALSE;

    public function __construct() {
        global $json_api;
        // allow only connection over https. because, well, you care about your passwords and sniffing.
        // turn this sanity-check off if you feel safe inside your localhost or intranet.
        if($this->SECURE) {
            if (empty($_SERVER['HTTPS']) ||
                (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == 'off')
            ) {
                if (empty($_REQUEST['insecure']) || $_REQUEST['insecure'] != 'cool') {
                    $json_api->error("SSL is not enabled. Either use _https_ or provide 'insecure' var as insecure=cool to confirm you want to use http protocol.");
                }
            }
        }
    }

    /**
     * Returns an Array with registered userid
     * @param String username: username to register
     * @param String email: email address for user registration
     * @param String password: password to be set (optional)
     * @param String displayname: displayname for user
     */
    public function register(){
        global $json_api;

        $username = sanitize_user( $_REQUEST['username'] );
        $email = sanitize_email( $_REQUEST['email'] );
        $password = sanitize_text_field( $_REQUEST['password'] );
        $displayname = sanitize_text_field( $_REQUEST['display_name'] );
        $user_first_name =  sanitize_text_field( $_REQUEST['user_first_name'] );
        $user_last_name = sanitize_text_field( $_REQUEST['user_last_name'] );
        $user_facebook_id = sanitize_text_field( $_REQUEST['user_last_name'] );

        //Add usernames we don't want used
        $invalid_usernames = array( 'admin' );
        //Do username validation
        $nonce_id = $json_api->get_nonce_id('user', 'register');

        if (!$username) {
            $msg = "You must include a 'username' var in your request.";
        } elseif (empty($_REQUEST['nonce'])) {
            $msg = "You must include a 'nonce' value. Use the 'get_nonce' Core API method.";
        } elseif( !wp_verify_nonce($json_api->query->nonce, $nonce_id) ) {
            $msg = "Invalid access, unverifiable 'nonce' value.";
        } elseif ( !$displayname ) {
            $msg = "You must include a 'display_name' var in your request.";
            /*} elseif ( !$user_first_name ) {
               $msg = "You must include a 'user_first_name' var in your request.";
            } elseif ( !$user_last_name ) {
               $msg = "You must include a 'user_last_name' var in your request.";*/
        } else {
            if ( !validate_username( $username ) || in_array( $username, $invalid_usernames ) ) {
                $msg = 'Username is invalid.';
            } elseif ( username_exists( $username ) ) {
                $msg = 'Username already exists.';
            } else {
                if (!$email) {
                    $msg = "Please use a valid email address.";
                } else {
                    if ( !is_email( $email ) ) {
                        $msg = "E-mail address is invalid.";
                    } elseif (email_exists($email)) {
                        $msg = "E-mail address is already in use.";
                    } else {
                        //Everything has been validated, proceed with creating the user
                        //Create the user
                        if( empty($password) )
                            $user_pass = wp_generate_password();
                        else
                            $user_pass = $password;

                        $user = array(
                            'user_login' => $username,
                            'user_pass' => $user_pass,
                            'display_name' => $displayname,
                            'user_email' => $email
                        );

                        $user_id = wp_insert_user( $user );

                        // Add additional parameters for the user data
                        /*add_user_meta( $user_id, 'user_first_name', $user_first_name, false );
                        add_user_meta( $user_id, 'user_last_name', $user_last_name, false );*/

                        // Send e-mail to admin and new user -
                        // You could create your own e-mail instead of using this function
                        wp_new_user_notification( $user_id, $user_pass );

                        if($user_id)
                            $msg = 'Success';
                    }

                }

            }
        }

        return array(
            "msg" => $msg,
            "user_id" => $user_id
        );
    }

    /**
     * Returns a session for active user
     * @param String nonce : A unique identifier for the user per this method
     * @param String email: The user email
     * @param String password: The user password
     */
    public function login() {
        // Method variables
        global $json_api;
        $msg = "error";
        $status = -1;
        $cookie = -1;
        $user_id = -1;
        $expiration = -1;
        $avatar = -1;

        // Get the nonce
        $nonce = $this->getSafeText($_REQUEST['nonce']);//trim(sanitize_text_field($_REQUEST['nonce']));
        $nonce_id = $json_api->get_nonce_id('user', 'login');

        // Get the user parameters that is required by wordpress
        $email = $this->getSafeText($_REQUEST['email']);//trim(sanitize_email($_REQUEST['email']));
        $password = $this->getSafeText($_REQUEST['password']);//trim(sanitize_text_field($_REQUEST['password']));

        if (!$nonce) {
            $msg = "You must include 'nonce' var in your request. Use the 'get_nonce' Core API method.";
        } elseif (!$email) {
            $msg = "You must include 'email' var in your request.";
        } elseif (!is_email($email)) {
            $msg = "E-mail address is invalid.";
        } elseif (!email_exists($email)) {
            $msg = "E-mail address doesn't exist.";
        } elseif (!$password) {
            $msg = "You must include 'password' var in your request.";
        } elseif (!wp_verify_nonce($nonce, $nonce_id)) {
            $msg = "Your 'nonce' value was incorrect. Use the 'get_nonce' API method.";
        } else {

            // Get the user from the email
            $user = get_user_by('email', $email);
            $username = $user->user_login;

            // All the parameters are ok try and authenticate the user
            $user = wp_authenticate($username, $password);
            if (is_wp_error($user)) {
                $msg = "Invalid username and/or password.";
                remove_action('wp_login_failed', $username);
            } else {

                // Generate a cookie for two weeks
                $status = 1;
                $msg = "ok";
                $expiration = time() + apply_filters('auth_cookie_expiration', 60 * 60 * 24 * 14, $user->ID, true);
                $cookie = wp_generate_auth_cookie($user->ID, $expiration, 'logged_in');
                $user_id = $user->ID;
                //preg_match('|src="(.+?)"|', get_avatar($user->ID, 32), $avatar);

                // Get the user profile pic
                $target_file = "/var/www/pics/" . $user->ID . "/" . $user->ID . ".jpg";
                if (file_exists($target_file)) {
                    //$avatar = $target_file;
                    $path = "http://" . SERVER_URL . "/pics/" . $user->ID . "/" . $user->ID . ".jpg";
                    $avatar = strtr($path, array('\\' => '/'));//str_replace("\\","/",$path);
                }
            }
        }

        return json_encode(array(
            "status" => $status,
            "msg" => $msg,
            "expiration" => $expiration,
            "cookie" => $cookie,
            "user_id" => $user_id,
            "avatar" => $avatar
        ), JSON_UNESCAPED_SLASHES);
    }

    public function upload() {
        // Method variables
        global $json_api;
        $msg = "error";
        $status = -1;
        $cookie = -1;
        $uploadOk = 1;

        // Get the data
        $cookie = trim(sanitize_text_field($_REQUEST['cookie']));//$this->getSafeText($_REQUEST['cookie']);//

        if (!$cookie) {
            $msg = "You must include a 'cookie' var in your request.";
        } else {
            $user_id = wp_validate_auth_cookie($cookie, 'logged_in');
            if (!$user_id) {
                $msg = "Invalid authentication cookie.";
            } else {
                // Get the relevant data for the user
                // And create the directory for him
                $user = get_userdata($user_id);
                $target_dir = "/var/www/pics/" . $user->ID;
                if (!file_exists($target_dir)) {
                    mkdir($target_dir, 0777, true);
                }

                // Check if image file is a actual image or fake image
                if (isset($_POST["submit"])) {
                    $check = getimagesize($_FILES["file"]["tmp_name"]);
                    if ($check !== false) {
                        $msg = "File is an image.";
                        $uploadOk = 1;
                    } else {
                        $msg = "File is not an image.";
                        $uploadOk = 0;
                    }
                }

                // Check file size
                if ($_FILES["file"]["size"] > 100 * KB) {
                    $msg = "Sorry, your file is too large.";
                    $uploadOk = 0;
                }

                // Create the file for upload
                $imageFileType = pathinfo($_FILES["file"]["name"], PATHINFO_EXTENSION);

                // Allow certain file formats
                if ($imageFileType != "jpg" && $imageFileType != "jpeg") {//&& $imageFileType != "png"
                    // && $imageFileType != "gif" ) {
                    $msg = "Sorry, only JPG & JPEG files are allowed.";
                    $uploadOk = 0;
                }

                $target_file = $target_dir . "/" . $user->ID . "." . $imageFileType;//basename($_FILES["file"]["name"]);
                // Check if $uploadOk is set to 0 by an error
                // if everything is ok, try to upload file
                if ($uploadOk == 0) {
                    //$msg = "Sorry, your file was not uploaded.";
                } else {
                    if (move_uploaded_file($_FILES["file"]["tmp_name"], $target_file)) {
                        $status = 1;
                        $msg = "The file has been uploaded.";
                    } else {
                        $msg = "Sorry, there was an error uploading your file.";
                    }
                }
            }
        }

        return json_encode(array(
            "status" => $status,
            "msg" => $msg
        ));
    }

    public function report_online()
    {

        // Methos variables
        global $wpdb;
        global $json_api;
        $status = -1;
        $msg = "error";
        $cookie = trim(sanitize_text_field($_REQUEST['cookie']));//$this->getSafeText($_REQUEST['cookie']);
        $lat = $this->getSafeText($_REQUEST['lat']);//trim(sanitize_text_field( $_REQUEST['lat'] ));
        $lng = $this->getSafeText($_REQUEST['lng']);//trim(sanitize_text_field( $_REQUEST['lng'] ));
        $city = $this->getSafeText($_REQUEST['city']);//trim(sanitize_text_field( $_REQUEST['city'] ));
        $table_location = $wpdb->prefix . "location";


        // Check all of the parameters
        if (!$cookie) {
            $msg = "You must include 'cookie' var in your request.";
        } elseif (!$lat) {
            $msg = "You must include 'lat' var in your request.";
        } elseif (!is_numeric($lat)) {
            $msg = "Latitude can only be a number.";
        } elseif (!$lng) {
            $msg = "You must include 'lng' var in your request.";
        } elseif (!is_numeric($lng)) {
            $msg = "Longitude can only be a number.";
        } elseif (!$city) {
            $msg = "You must include 'city' var in your request.";
        } else {

            $user_id = wp_validate_auth_cookie($cookie, 'logged_in');
            if (!$user_id) {
                $msg = "Invalid authentication cookie.";
            } else {
                $status = 1;
                $msg = "ok";
                $data = array("id" => $user_id,
                    "latitude" => $lat,
                    "longitude" => $lng,
                    "city" => $city,
                    "online" => "1");
                $wpdb->replace($table_location, $data);
            }
        }

        return json_encode(array(
            "status" => $status,
            "msg" => $msg,
        ));
    }

    public function report_offline()
    {

        // Methos variables
        global $wpdb;
        global $json_api;
        $status = -1;
        $msg = "error";
        $cookie = trim(sanitize_text_field($_REQUEST['cookie']));//$this->getSafeText($_REQUEST['cookie']);//
        $table_location = $wpdb->prefix . "location";


        // Check all of the parameters
        if (!$cookie) {
            $msg = "You must include 'cookie' var in your request.";
        } else {

            $user_id = wp_validate_auth_cookie($cookie, 'logged_in');
            if (!$user_id) {
                $msg = "Invalid authentication cookie.";
            } else {
                $status = 1;
                $msg = "ok";
                $data = array("id" => $user_id);
                $wpdb->delete($table_location, $data);
            }
        }

        return json_encode(array(
            "status" => $status,
            "msg" => $msg,
        ));
    }

    /**
     * Add a cigarette info to the cigarette info table
     * @param cookie the user cookie session
     * @param user_id The user id
     * @param password the user password
     */
    public function remove_account() {

        // Methos variables
        global $wpdb;
        global $json_api;
        $status = "error";
        $cookie = sanitize_text_field( $_REQUEST['cookie'] );
        $user_id = sanitize_text_field( $_REQUEST['user_id'] );
        $user_email = sanitize_text_field( $_REQUEST['email'] );
        $password = sanitize_text_field( $_REQUEST['password'] );
        $table_orders = $wpdb->prefix . "orders";
        $table_users = $wpdb->prefix . "users";
        $table_users_meta = $wpdb->prefix . "usermeta";

        // Error messages
        $error_missing_variables = "Some variables are missing on your request.";
        $error_session_old_or_invalid = "Your session is either old or invalid please login again.";
        $problem_inserting_new_data = "An error has occured while trying to insert new data.";

        // Check for a valid nonce value
        $nonce_id = $json_api->get_nonce_id('user', 'remove_account');
        $user = wp_authenticate_using_email($user_email, $password);

        // In case the password and email are ok get the user id from the $user object
        if (!is_wp_error($user)) {
            $user_id = $user->ID;
        }
        // Check all of the parameters
        if (!$cookie) {
            $msg = $error_session_old_or_invalid;
        } elseif (empty($_REQUEST['cookie']) || empty($_REQUEST['user_id']) || empty($_REQUEST['password'])) {
            $msg = $error_missing_variables;
        } elseif( !wp_verify_nonce($json_api->query->nonce, $nonce_id) ) {
            $msg = "Invalid access, unverifiable 'nonce' value.";
        } elseif ( !$user_id ) {
            $msg = "You must include a 'user_id' var in your request.";
        } elseif ( !$password ) {
            $msg = "You must include a 'password' var in your request.";
        } elseif ( is_wp_error($user) ) {
            $msg = "The email or password provided are incorrect.";
        } else {
            // Attempt to insert the new data to the database
            $isValidCookie = wp_validate_auth_cookie($cookie, 'logged_in') ? true : false;

            if($isValidCookie) {
                $removed_from_users = $wpdb->delete( $table_users , array( 'ID' => $user_id ), array( '%d' ) );
                $removed_from_orders = $wpdb->delete( $table_orders , array( 'user_id' => $user_id ), array( '%d' ) );
                $removed_from_users_meta = $wpdb->delete( $table_users_meta , array( 'user_id' => $user_id ), array( '%d' ) );

                if($removed_from_orders || $removed_from_users || $removed_from_users_meta ) {
                    $msg = "Your account has been removed from our system";
                }
                $status = "ok";
            } elseif(!$isValidCookie) {
                $msg = $error_session_old_or_invalid;
            }
        }

        return array(
            "status" => $status,
            "msg" => $msg,
        );
    }


    /**
     * Add a cigarette info to the cigarette info table
     * @param user_id The user id
     * @param cigarette_id the cigarette id
     * @param number_of_puffs the number of puffs the user took from the flavor
     * @param flavor_taste the flavor taste
     * @param cookie the user cookie session
     */
    public function order_cigarette_flavor() {

        // Methos variables
        global $wpdb;
        global $json_api;
        $status = "error";
        $table_orders = $wpdb->prefix . "orders";
        $cookie = sanitize_text_field( $_REQUEST['cookie'] );
        $user_id = sanitize_text_field( $_REQUEST['user_id'] );
        $flavor = sanitize_text_field( $_REQUEST['cigarette_flavor'] );

        // Error messages
        $error_missing_variables = "Some variables are missing on your request.";
        $error_session_old_or_invalid = "Your session is either old or invalid please login again.";
        $problem_inserting_new_data = "An error has occured while trying to insert new data.";

        // Check for a valid nonce value
        $nonce_id = $json_api->get_nonce_id('user', 'order_cigarette_flavor');


        // Check all of the parameters
        if (!$cookie) {
            $msg = $error_session_old_or_invalid;
        } elseif (empty($_REQUEST['cookie']) || empty($_REQUEST['user_id']) || empty($_REQUEST['cigarette_flavor'])) {
            $msg = $error_missing_variables;
        } elseif( !wp_verify_nonce($json_api->query->nonce, $nonce_id) ) {
            $msg = "Invalid access, unverifiable 'nonce' value.";
        } elseif ( !$user_id ) {
            $msg = "You must include a 'user_id' var in your request.";
        } elseif ( !$flavor ) {
            $msg = "You must include a 'flavor' var in your request.";

        } else {

            // Attempt to insert the new data to the database
            $isValidCookie = wp_validate_auth_cookie($cookie, 'logged_in') ? true : false;

            if($isValidCookie) {
                $inserted = $wpdb->insert( $table_orders,
                    array( 'user_id' => $user_id, 'flavor' => $flavor ),
                    array( '%d', '%s' ) );

                $row_id = $wpdb->insert_id;

                if($inserted) {
                    $msg = "Row added succesfully";
                }
                $status = "ok";
            } elseif(!$isValidCookie) {
                $msg = $error_session_old_or_invalid;
            }
        }

        return array(
            "status" => $status,
            "msg" => $msg,
        );
    }

    /**
     * Validates an authentication cookie
     * @param String cookie: The current session cookie
     */
    public function validate_auth_cookie() {
        global $json_api;

        if (!$json_api->query->cookie) {
            $json_api->error("You must include a 'cookie' authentication cookie. Use the `create_auth_cookie` Auth API method.");
        }

        $valid = wp_validate_auth_cookie($json_api->query->cookie, 'logged_in') ? true : false;

        return array(
            "valid" => $valid
        );
    }

    /**
     * Generates an authentication cookie which is valid for 14 days
     * @param String username: username to authenticate
     * @param String password: the user password
     */
    public function generate_auth_cookie() {
        global $json_api;

        $nonce_id = $json_api->get_nonce_id('user', 'generate_auth_cookie');
        if (!wp_verify_nonce($json_api->query->nonce, $nonce_id)) {
            $json_api->error("Your 'nonce' value was incorrect. Use the 'get_nonce' API method.");
        }

        if (!$json_api->query->username) {
            $json_api->error("You must include a 'username' var in your request.");
        }

        if (!$json_api->query->password) {
            $json_api->error("You must include a 'password' var in your request.");
        }

        $user = wp_authenticate($json_api->query->username, $json_api->query->password);
        if (is_wp_error($user)) {
            $json_api->error("Invalid username and/or password.", 'error', '401');
            remove_action('wp_login_failed', $json_api->query->username);
        }

        // A cookie will expire after 1 month - 60*60*24*31
        $expiration = time() + apply_filters('auth_cookie_expiration', 2678400, $user->ID, true);

        $cookie = wp_generate_auth_cookie($user->ID, $expiration, 'logged_in');
        $time = gmdate("Y-m-d\TH:i:s\Z", $expiration);
        return array(
            "cookie" => $cookie,
            "expiration" => $time,
            "id" => $user->ID,
            "user" => array(
                "username" => $user->user_login,
                "nicename" => $user->user_nicename,
                "email" => $user->user_email,
                "url" => $user->user_url,
                "registered" => $user->user_registered,
                "displayname" => $user->display_name,
                "firstname" => $user->user_firstname,
                "lastname" => $user->last_name,
                "nickname" => $user->nickname,
                "description" => $user->user_description,
                "capabilities" => $user->wp_capabilities,
            ),
        );
    }

    /**
     * Generates an authentication cookie which is valid for 14 days
     * @param String email: the email to authenticate
     * @param String password: the user password
     */
    public function generate_auth_cookie_by_email() {
        global $json_api;
        global $wpdb;

        $nonce_id = $json_api->get_nonce_id('user', 'generate_auth_cookie_by_email');
        if (!wp_verify_nonce($json_api->query->nonce, $nonce_id)) {
            $json_api->error("Your 'nonce' value was incorrect. Use the 'get_nonce' API method.");
        }

        if (!$json_api->query->email) {
            $json_api->error("You must include a 'username' var in your request.");
        }

        if (!$json_api->query->password) {
            $json_api->error("You must include a 'password' var in your request.");
        }

        $user = wp_authenticate_using_email($json_api->query->email, $json_api->query->password);
        if (is_wp_error($user)) {
            $json_api->error("Invalid username and/or password.", 'error', '401');
            remove_action('wp_login_failed', $json_api->query->username);
        }

        // Get additional user metadata_
        $user_first_name = get_user_meta($user->ID, 'user_first_name' , false);
        if (is_wp_error($user_meta_data)) {
            $json_api->error("No additional user metadata.", 'error', '401');
        }

        $user_last_name = get_user_meta($user->ID, 'user_last_name' , false);
        if (is_wp_error($user_meta_data)) {
            $json_api->error("No additional user metadata.", 'error', '401');
        }

        $args = array("user_id" =>$user->ID);

        // The Query
        $user_query = new WP_User_Query( $args );


        // A cookie will expire after 1 month - 60*60*24*30
        $expiration = time() + apply_filters('auth_cookie_expiration', 2678400, $user->ID, true);

        $cookie = wp_generate_auth_cookie($user->ID, $expiration, 'logged_in');
        $time = gmdate("Y-m-d H:i:s", $expiration);
        return array(
            "cookie" => $cookie,
            "expiration" => $time,
            "id" => $user->ID,
            "user" => array(
                "username" => $user->user_login,
                "nicename" => $user->user_nicename,
                "email" => $user->user_email,
                "displayname" => $user->display_name,
                "firstname" => $user_first_name,
                "lastname" => $user_last_name,
                "meta" => $user_meta_data,
            ),
        );
    }

    /**
     * Gets the current user info
     * @param String cookie: Cookie for a single user session
     */
    public function get_currentuserinfo() {
        global $json_api;

        if (!$json_api->query->cookie) {
            $json_api->error("You must include a 'cookie' var in your request. Use the `generate_auth_cookie` Auth API method.");
        }

        $user_id = wp_validate_auth_cookie($json_api->query->cookie, 'logged_in');
        if (!$user_id) {
            $json_api->error("Invalid authentication cookie. Use the `generate_auth_cookie` Auth API method.");
        }

        $user = get_userdata($user_id);

        return array(
            "user" => array(
                "id" => $user->ID,
                "username" => $user->user_login,
                "nicename" => $user->user_nicename,
                "email" => $user->user_email,
                "url" => $user->user_url,
                "registered" => $user->user_registered,
                "displayname" => $user->display_name,
                "firstname" => $user->user_firstname,
                "lastname" => $user->last_name,
                "nickname" => $user->nickname,
                "description" => $user->user_description,
                "capabilities" => $user->wp_capabilities,
            )
        );
    }
}
