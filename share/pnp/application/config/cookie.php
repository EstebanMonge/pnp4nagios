<?php

defined('SYSPATH') or die('No direct access allowed.');

/**
 * Cookie settings. The session cookie is never read by JavaScript, so keep it
 * out of reach of scripts (limits the impact of any XSS).
 */
$config['httponly'] = true;
