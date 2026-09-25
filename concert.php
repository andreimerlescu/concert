<?php
declare(strict_types=1);

/**
 * concert.php: tell Concert who this visitor is.
 *
 * Concert reads one response header, on any page response:
 *
 *     Concert-Priority: <rank>[; ttl=<seconds>]
 *
 * and removes it before the response reaches the browser. The rank lives in
 * a signed cookie that only Concert can issue. The latest header wins, and
 * every header renews the rank's lifetime.
 *
 * Ranks, lowest to highest:
 *
 *     guest       anonymous, or clear a rank
 *     member      signed in, nothing bought yet
 *     prospect    on a buying page, or items in the cart
 *     customer    has bought before
 *     subscriber  has an active subscription
 *     checkout    payment in progress
 *     staff       operators and support
 *
 * The application decides the facts; Concert decides what each rank gets
 * when the site is busy.
 */

const CONCERT_RANKS = ['guest', 'member', 'prospect', 'customer', 'subscriber', 'checkout', 'staff'];
const CONCERT_SESSION_KEY = 'concert_rank';


require_once __DIR__ . '/concert.php';

$now = time();

// A visit to the buying page makes the visitor a prospect for 30 minutes,
// so browsing elsewhere and coming back to buy keeps the rank.
if (basename($_SERVER['SCRIPT_NAME'] ?? '') === 'buy.php') {
    $_SESSION['concert_prospect_until'] = $now + 1800;
}

concert_sync([
    // Operators and support staff.
    'staff'      => !empty($_SESSION['is_staff']),
    // Payment started in the last 30 minutes (see "Checkout" below).
    'checkout'   => ($_SESSION['checkout_started_at'] ?? 0) > $now - 1800,
    // An active subscription.
    'subscriber' => !empty($_SESSION['subscription_active']),
    // A purchase ID anywhere in the session's history.
    'customer'   => !empty($_SESSION['purchase_ids']),
    // Viewed buy.php recently, or has items in the cart.
    'prospect'   => ($_SESSION['concert_prospect_until'] ?? 0) > $now || !empty($_SESSION['cart']),
    // Signed in.
    'member'     => !empty($_SESSION['user_id']),
]);

// CHECKOUT

$_SESSION['checkout_started_at'] = time();

// SUCCESS

unset($_SESSION['checkout_started_at']);
$_SESSION['purchase_ids'][] = $purchaseId;   // whatever your app already does here

// LOGOUT

concert_clear();
session_destroy();

// VERIFY

// curl -s -D - -o /dev/null http://127.0.0.1:8080/concert.php | grep -i concert-priority


/**
 * The highest rank whose fact is true, or guest.
 *
 * @param array<string, bool> $facts keyed by rank name, e.g. ['member' => true]
 */
function concert_rank(array $facts): string
{
    for ($i = count(CONCERT_RANKS) - 1; $i > 0; $i--) {
        if (!empty($facts[CONCERT_RANKS[$i]])) {
            return CONCERT_RANKS[$i];
        }
    }
    return 'guest';
}

/**
 * Sends Concert-Priority on this response. Returns false when headers have
 * already been sent (output started), so the caller can log it.
 */
function concert_priority(string $rank, ?int $ttlSeconds = null): bool
{
    if (!in_array($rank, CONCERT_RANKS, true)) {
        throw new InvalidArgumentException("unknown Concert rank: {$rank}");
    }
    if (headers_sent()) {
        return false;
    }
    $value = $rank;
    if ($ttlSeconds !== null && $rank !== 'guest') {
        $value .= '; ttl=' . max(60, min(86400, $ttlSeconds));
    }
    header('Concert-Priority: ' . $value, true);
    return true;
}

/**
 * Sends the rank for the current visitor on every response that needs it.
 * A ranked visitor gets the header each time, which keeps the rank alive.
 * A visitor who drops to guest gets one "guest" to clear it. Anonymous
 * visitors who were never ranked get no header at all.
 *
 * Call it after session_start() and before any output.
 *
 * @param array<string, bool> $facts
 */
function concert_sync(array $facts, ?int $ttlSeconds = null): string
{
    $rank = concert_rank($facts);
    $hasSession = session_status() === PHP_SESSION_ACTIVE;
    $last = $hasSession ? ($_SESSION[CONCERT_SESSION_KEY] ?? 'guest') : 'guest';

    if ($rank === 'guest' && $last === 'guest') {
        return $rank; // nothing to grant, nothing to clear
    }
    if (concert_priority($rank, $ttlSeconds) && $hasSession) {
        $_SESSION[CONCERT_SESSION_KEY] = $rank;
    }
    return $rank;
}

/**
 * Clears the visitor's rank. Call it on logout, before destroying the
 * session: afterwards there is no record that a rank was ever sent.
 */
function concert_clear(): void
{
    concert_priority('guest');
    if (session_status() === PHP_SESSION_ACTIVE) {
        unset($_SESSION[CONCERT_SESSION_KEY]);
    }
}