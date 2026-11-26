# phpBB 3.3+ Integration Guide

`Concert\Adapters\PhpBbAdapter` maps phpBB's `$user->data` and `$auth` ACL permissions (`a_` admin, `m_` moderator) to `Concert-Priority` ranks.

## 1. Create a phpBB Event Listener

In your phpBB extension (`ext/concert/waitingroom/event/listener.php`):

```php
<?php
declare(strict_types=1);

namespace concert\waitingroom\event;

use Concert\Adapters\PhpBbAdapter;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

class listener implements EventSubscriberInterface
{
    private \phpbb\user $user;
    private \phpbb\auth\auth $auth;
    private PhpBbAdapter $adapter;

    public function __construct(\phpbb\user $user, \phpbb\auth\auth $auth)
    {
        $this->user = $user;
        $this->auth = $auth;
        // Pass any phpBB supporter group_id(s) that should receive 'subscriber' rank.
        $this->adapter = new PhpBbAdapter(subscriberGroupIds: [8]);
    }

    public static function getSubscribedEvents(): array
    {
        return [
            'core.page_header_after' => 'onPageHeaderAfter',
            'core.session_kill_after' => 'onSessionKillAfter',
        ];
    }

    public function onPageHeaderAfter(): void
    {
        $this->adapter->emitForPage($this->user->data, $this->auth);
    }

    public function onSessionKillAfter(): void
    {
        $this->adapter->clearOnLogout();
    }
}
```

## 2. Rank Mapping

| phpBB State | `Concert-Priority` Rank |
|---|---|
| `$auth->acl_get('a_')` or `$auth->acl_get('m_')` | `staff` |
| Registered user in `$subscriberGroupIds` | `subscriber` |
| Registered non-bot user (`user_id > 1`) | `member` |
| Anonymous (`user_id === 1`) or search bot (`is_bot`) | `guest` (no header emitted) |
| Logout (`core.session_kill_after`) | `guest` (clears prior grant) |
