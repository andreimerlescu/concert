<?php
declare(strict_types=1);

/**
 * Plugin Name:       Concert Waiting Room & Cache for WordPress
 * Plugin URI:        https://github.com/andreimerlescu/concert
 * Description:       Automatic Concert-Priority ranking for WordPress & WooCommerce visitors and authenticated active cache purging for wpconcert / concert-cache.
 * Version:           0.3.0
 * Requires at least: 6.0
 * Requires PHP:      8.1
 * Author:            Concert Contributors
 * License:           Apache-2.0
 * License URI:       https://www.apache.org/licenses/LICENSE-2.0
 * Text Domain:       concert-wp
 */

if (!defined('ABSPATH')) {
    exit;
}

require_once __DIR__ . '/includes/Secret.php';
require_once __DIR__ . '/includes/UrlValidator.php';
require_once __DIR__ . '/includes/PriorityClassifier.php';
require_once __DIR__ . '/includes/CachePurger.php';
require_once __DIR__ . '/includes/AdminBar.php';
require_once __DIR__ . '/includes/Plugin.php';

\Concert\WordPress\Plugin::bootstrap();
