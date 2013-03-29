<?php

/**
 * @file
 * Internal class to use twitter API
 *
 * Thanks to Matt Harris I use the lib to create this one more basic.
 * https://github.com/themattharris/tmhOAuth
 */

class TwitterQueue {
  const VERSION = 0.01;

  public function __construct($config) {
    $this->config = array_merge(
      array(
        'use_ssl'                    => true,
        'host'                       => 'api.twitter.com',

        'consumer_key'               => '',
        'consumer_secret'            => '',
        'user_token'                 => '',
        'user_secret'                => '',
        'nonce'                      => false,
        'force_timestamp'            => false,
        'timestamp'                  => false,

        'oauth_version'              => '1.0',
        'oauth_signature_method'     => 'HMAC-SHA1',

        'curl_connecttimeout'        => 30,
        'curl_timeout'               => 10,

        // for security this should always be set to 2. I read that in Internet :)
        'curl_ssl_verifyhost'        => 2,
        // for security this should always be set to true.
        'curl_ssl_verifypeer'        => true,

        // you can get the latest cacert.pem from here http://curl.haxx.se/ca/cacert.pem
        'curl_cainfo'                => dirname(__FILE__) . '/cacert.pem',
        'curl_capath'                => dirname(__FILE__),

        // streaming API
        'is_streaming'               => false,
        'streaming_eol'              => "\r\n",
        'streaming_metrics_interval' => 60,

        // header or querystring. You should always use header!
        // this is just to help me debug other developers implementations
        'as_header'                  => true,
        'debug'                      => false,
      ),
      $config
    );
  }

  /**
   * Generates a timestamp.
   * If 'force_timestamp' is true a nonce is not generated and the value in the configuration will be retained.
   *
   * @return void
   */
  private function create_timestamp() {
    $this->config['timestamp'] = ($this->config['force_timestamp'] == false ? time() : $this->config['timestamp']);
  }

  /**
   * Returns an array of the standard OAuth parameters.
   *
   * @return array all required OAuth parameters, safely encoded
   */
  private function get_defaults() {
    $defaults = array(
      'oauth_version'          => $this->config['oauth_version'],
      'oauth_nonce'            => $this->config['nonce'],
      'oauth_timestamp'        => $this->config['timestamp'],
      'oauth_consumer_key'     => $this->config['consumer_key'],
      'oauth_signature_method' => $this->config['oauth_signature_method'],
    );

    if ($this->config['user_token']) {
      $defaults['oauth_token'] = $this->config['user_token'];
    }

    // safely encode
    foreach ($defaults as $key => $value) {
      $_defaults[OAuthUtil::urlencode_rfc3986($key)] = OAuthUtil::urlencode_rfc3986($value);
    }

    return $_defaults;
  }

  /**
   * Prepare the HTTP method for use in the base string.
   *
   * @param string $method an HTTP method such as GET or POST
   *
   * @return void value is stored to a class variable
   */
  private function prepare_method($method){
    $this->method = strtoupper($method);
  }

  /**
   * Prepares the URL for use in the base string by ripping it apart and
   * reconstruction it.
   *
   * @param string $uel the request URL
   *
   * @return voidvalue is stored to a class variable
   */
  private function prepare_url($url) {
    $parts = parse_url($url);

    $port   = !empty($parts['port']) ? $parts['port'] : false;
    $scheme = $parts['scheme'];
    $host   = $parts['host'];
    $path   = !empty($parts['path']) ? $parts['path'] : false;

    $port || $port = ($scheme == 'https') ? '443' : 80;

    if (($scheme == 'https' && $port != '443')
      || ($scheme == 'http' && $port != '80')) {
      $host = "{$host}:{$port}";
    }
    $this->url =strtolower("{$scheme}://{$host}{$path}");
  }

  /**
   * Prepares all parameters for the base string and request.
   * Multipart parameters are ignored as they are not defined in the specification,
   * all other types of parameter are encoded for compatibility with OAuth.
   *
   * @param array $params the parameters for the request
   * @return void prepared values are stored in class variables
   */
  private function prepare_params($params) {
    // multipart parameters, leave them alone
    if ($this->config['multipart']) {
      $this->request_params = $params;
      $params = array();
    }

    $this->signing_params = array_merge($this->get_defaults(), (array)$params);

    // remove oauth_signature if present
    // ref: spec: 9.1.1 ("The oauth_signature parameter MUST be excluded.")
    if (isset($this->signing_params['oauth_signature'])) {
      unset($this->signing_params['oauth_signature']);
    }

    // Parameters are sorted bu name, using lexicographical bte value ordering.
    uksort($this->signing_params, 'strcmp');

    // encode. Also sort the signed parameters from the POST parameters
    foreach ($this->signing_params as $key => $value) {
      $key   = OAuthUtil::urlencode_rfc3986($key);
      $value = OAuthUtil::urlencode_rfc3986($value);
      $_signing_params[$key] = $value;
      $keyvalue[] = "{$key}={$value}";
    }

    // auth params = the default oauth params which are present in our collection of signing params
    $this->auth_params = array_intersect_key($this->get_defaults(), $_signing_params);
    if (isset($_signing_params['oauth_callback'])) {
      $this->auth_params['oauth_callback'] = $_signing_params['oauth_callback'];
      unset($_signing_params['oauth_callback']);
    }

    if (isset($_signing_params['oauth_verifier'])) {
      $this->auth_params['oauth_verifier'] = $_signing_params['oauth_verifier'];
      unset($_signing_params['oauth_verifier']);
    }

    // request_params is already set if we're doing multipart, if not we need to set them now
    if (!$this->config['multipart']){
      $this->request_params = array_diff_key($_signing_params, $this->get_defaults());
    }

    // create the parameter part of the base string
    $this->signing_params = implode('&', $keyvalue);
  }

  /**
   * Prepares the OAuth signing key
   *
   * @return void prepared signing key is stored in a class variables
   */
  private function prepare_signing_key() {
    $this->signing_key = OAuthUtil::urlencode_rfc3986($this->config['consumer_secret']) . '&' . OAuthUtil::urlencode_rfc3986($this->config['user_secret']);
  }

  /**
   * Prepare the base string.
   * Ref: Spec: 9.1.3 ("Concatenate Rquest Elements")
   *
   * @return void prepared base string is stored in a class variables
   */
  private function prepare_base_string() {
    // OAuthUtil::urlencode_rfc3986($input)
    $base = array(
      $this->method,
      $this->url,
      $this->signing_params,
    );
    $this->base_string = implode('&', OAuthUtil::urlencode_rfc3986($base));
  }

  /**
   * Prepares the Authorization header
   *
   * @return void prepared authorization header is stored in a class variables
   */
  private function prepare_auth_header() {
    $this->headers = array();
    uksort($this->auth_params, 'strcmp');
    if (!$this->config['as_header']) :
      $this->request_params = array_merge($this->request_params, $this->auth_params);
      return;
    endif;

    foreach ($this->auth_params as $key => $value) {
      $kv[] = "{$key}=\"{$value}\"";
    }
    $this->auth_header = 'OAuth ' . implode(', ', $kv);
    $this->headers['Authorization'] = $this->auth_header;
  }

  /**
   * Signs the request and adds the OAuth signature. This runs all the request
   * parameter preparation methos.
   *
   * @param string $method the HTTP being used. ex POST, GET, HEAD etc
   * @param string $url the request URL without query string parameters.
   * @param array $params the request parameters as an array of key=value pairs
   * @param string $useauth whether to use authentication when making the request.
   */
  private function sign($method, $url, $params, $useauth) {
    $this->prepare_method($method);
    $this->prepare_url($url);
    $this->prepare_params($params);

    // we don't sign anything is we're not using auth
    if ($useauth) {
      $this->prepare_base_string();
      $this->prepare_signing_key();

      $this->auth_params['oauth_signature'] = OAuthUtil::urlencode_rfc3986(base64_encode(hash_hmac('sha1', $this->base_string, $this->signing_key, true)));
    }
    $this->prepare_auth_header();
  }

  /**
   * Make an HTTP request using this library. This method doesn't return anything.
   * Instead the response should be inspected directly.
   *
   */
  public function request($method, $url, $params = array(), $useauth = true, $multipart = false) {
    $this->config['multipart'] = $multipart;

    $this->create_timestamp();

    $this->sign($method, $url, $params, $useauth);
    return $this->curlit();
  }


  /**
   * Make an HTTP request using this library. This method doesn't return anything.
   * Instead the response should be inspected directly.
   *
   * @param string $method the HTTP method being used. e.g. POST, GET, HEAD etc
   * @param string $url the request URL without query string parameters
   * @param array $params the request parameters as an array of key=value pairs
   * @param string $useauth whether to use authentication when making the request. Default true.
   * @param string $multipart whether this request contains multipart data. Default false
   */
  public function url($request, $format = 'json') {
    $format = strlen($format) > 0 ? ".$format" : '';
    $proto = $this->config['use_ssl'] ? 'https:/' : 'http:/';

    // backwards compatibility with v0.1
    if (isset($this->config['v']))
      $this->config['host'] = $this->config['host'] . '/' . $this->config['v'];

    return implode('/', array(
      $proto,
      $this->config['host'],
      $request . $format
    ));
  }

  /**
   * Utility function to parse the returned curl headers and store them in the
   * class array variable.
   *
   * @param object $ch curl handle
   * @param string $header the response headers
   * @return the string length of the header
   */
  private function curlHeader($ch, $header) {
    $i = strpos($header, ':');
    if (!empty($i) ) {
      $key = str_replace('-', '_', strtolower(substr($header, 0, $i)));
      $value = trim(substr($header, $i + 2));
      $this->response['headers'][$key] = $value;
    }
    return strlen($header);
  }

  private function curlit() {
    // method handling. I'm gonna comment this lines just because I'm gonna
    // user only POST, in case I need use another method just uncomment this.
    /* -- delete this line to active this piece of code.
    switch ($this->method) {
      case 'POST':
        break;

      default:
        # GET, DELETE request so convert the parameters to a querystring
        if (!empty($this->request_params)) {
          foreach ($this- request_params as $key => $value) {
            // multipart GET?, w/e some support for it
            if ($this->config['multipart']) {
              $params[] = OAuthUtil::urlencode_rfc3986($key) . '=' . OAuthUtil::urlencode_rfc3986($value);
            }
          }
          $qs = implode('&', $params);
          $this->url = strlen($qs) > 0 ? $this->url . '?' . $qs : $this->url;
          $this->request_params = array();
        }
        break;
    }
    // */

    // configure curl
    $c = curl_init();
    curl_setopt_array($c, array(
      CURLOPT_CONNECTTIMEOUT => $this->config['curl_connecttimeout'],
      CURLOPT_TIMEOUT        => $this->config['curl_timeout'],
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_SSL_VERIFYPEER => $this->config['curl_ssl_verifypeer'],
      CURLOPT_SSL_VERIFYHOST => $this->config['curl_ssl_verifyhost'],

      CURLOPT_FOLLOWLOCATION => false,
      CURLOPT_PROXY          => false,
      CURLOPT_ENCODING       => '',
      CURLOPT_URL            => $this->url,
      // headers
      CURLOPT_HEADERFUNCTION => array($this, 'curlHeader'),
      CURLOPT_HEADER         => false,
      CURLINFO_HEADER_OUT    => true,
    ));

    if ($this->config['curl_cainfo'] !== FALSE) {
      curl_setopt($c, CURLOPT_CAINFO, $this->config['curl_cainfo']);
    }

    if ($this->config['curl_capath'] !== FALSE) {
      curl_setopt($c, CURLOPT_CAPATH, $this->config['curl_capath']);
    }


    switch ($this->method) {
      case 'GET':
        break;
      case 'POST':
        curl_setopt($c, CURLOPT_POST, true);
        break;
      default:
        curl_setopt($c, CURLOPT_CUSTOMREQUEST, $this->method);
    }

    if (!empty($this->request_params) ) {
      // if not doing multipart we need to implode the parameters
      if (!$this->config['multipart'] ) {
        foreach ($this->request_params as $key => $value) {
          $ps[] = "{$key}={$value}";
        }
        $this->request_params = implode('&', $ps);
      }
      curl_setopt($c, CURLOPT_POSTFIELDS, $this->request_params);
    }
    else {
      // CURL will set length to -1 when there is no data, which breaks Twitter
      $this->headers['Content-Type']   = '';
      $this->headers['Content-Length'] = '';
    }

    // CURL defaults to setting this to Expect: 100-Continue which Twitter rejects
    $this->headers['Expect'] = '';

    if (!empty($this->headers)) {
      foreach ($this->headers as $key => $value) {
        $headers[] = trim($key . ': ' . $value);
      }
      curl_setopt($c, CURLOPT_HTTPHEADER, $headers);
    }

    if (isset($this->config['prevent_request']) && true == $this->config['prevent_request']) {
      return;
    }

    // do it!
    $response = curl_exec($c);
    $code     = curl_getinfo($c, CURLINFO_HTTP_CODE);
    $info     = curl_getinfo($c);
    $error    = curl_error($c);
    $errno    = curl_errno($c);
    curl_close($c);

    // store the response
    $this->response['code']     = $code;
    $this->response['response'] = $response;
    $this->response['info']     = $info;
    $this->response['error']    = $error;
    $this->response['errno']    = $errno;
    return $code;
  }
}
