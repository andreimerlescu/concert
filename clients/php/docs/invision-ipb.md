# Invision Power Board (IPB / IPS Community Suite) Integration Guide

`Concert\Adapters\InvisionAdapter` maps IPS member groups, ACP/moderator status, and IPS Commerce checkout/subscription state to Concert's `Concert-Priority` header, and exposes a topic purge helper for `wpconcert` / `concert-cache`.

## 1. Emit `Concert-Priority` in an IPS Output Hook

Hook `\IPS\Output::sendOutput()` in a lightweight IPS application or plugin:

```php
<?php
declare(strict_types=1);

use Concert\Adapters\InvisionAdapter;

class concert_hook_output extends _HOOK_CLASS_
{
    public function sendOutput($output, $httpStatusCode = 200, $contentType = 'text/html', $httpHeaders = array(), $cacheThisPage = true, $pageIsCached = false, $parseFileObjects = true, $parseEmoji = true)
    {
        $member = \IPS\Member::loggedIn();
        $adapter = new InvisionAdapter(
            staffGroupIds: [4, 6],      // Administrators & Moderators
            subscriberGroupIds: [9]     // Paid supporter group ID (customize to your IPS groups)
        );

        $adapter->emitForMember(
            member: [
                'member_id'       => (int) $member->member_id,
                'member_group_id' => (int) $member->member_group_id,
                'mgroup_others'   => (string) $member->mgroup_others,
                'is_acp'          => $member->isAdmin(),
                'is_mod'          => (bool) $member->modPermission(),
            ],
            commerce: [
                'checkout_active'  => isset(\IPS\Request::i()->app) && \IPS\Request::i()->app === 'nexus' && (\IPS\Request::i()->module ?? '') === 'checkout',
                'cart_items'       => isset($_SESSION['cart']) && is_array($_SESSION['cart']) ? count($_SESSION['cart']) : 0,
            ]
        );

        return parent::sendOutput($output, $httpStatusCode, $contentType, $httpHeaders, $cacheThisPage, $pageIsCached, $parseFileObjects, $parseEmoji);
    }
}
```

## 2. Purge Cached Topic Pages on New Posts

```php
<?php
declare(strict_types=1);

use Concert\Adapters\InvisionAdapter;
use Concert\CachePurgeClient;
use Concert\Secret;

$purger = new CachePurgeClient(
    'https://127.0.0.1:8080',
    Secret::fromFile('/run/secrets/concert_admin_token')
);

InvisionAdapter::purgeTopic($purger, '/topic/1234-release-notes/', 1234, 'community.example.com');
```
