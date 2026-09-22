{{template "header" .}}
{{if not .Authed}}
<div class="row justify-content-center">
  <div class="col-sm-9 col-md-6 col-lg-4">
    <div class="card stat-card mt-5">
      <div class="card-body p-4">
        <h1 class="h4 mb-1"><i class="bi bi-shield-lock"></i> Portal sign in</h1>
        <p class="text-body-secondary small mb-4">Enter the portal pass to manage this concert.</p>
        {{if .Error}}<div class="alert alert-danger py-2" role="alert"><i class="bi bi-exclamation-triangle"></i> {{.Error}}</div>{{end}}
        <form method="post" action="/login" autocomplete="off">
          <label for="pass" class="form-label">Portal pass</label>
          <input type="password" class="form-control mb-3" id="pass" name="pass" required autofocus>
          <button type="submit" class="btn btn-primary w-100"><i class="bi bi-box-arrow-in-right"></i> Sign in</button>
        </form>
      </div>
    </div>
  </div>
</div>
{{else}}
<div id="portal-app">
  <ul class="nav nav-tabs mb-4" role="tablist">
    <li class="nav-item" role="presentation">
      <button class="nav-link active" id="tab-overview-btn" data-bs-toggle="tab" data-bs-target="#tab-overview" type="button" role="tab" aria-controls="tab-overview" aria-selected="true">
        <i class="bi bi-speedometer2"></i> Overview
      </button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link" id="tab-queue-btn" data-bs-toggle="tab" data-bs-target="#tab-queue" type="button" role="tab" aria-controls="tab-queue" aria-selected="false">
        <i class="bi bi-people"></i> Queue <span class="badge rounded-pill text-bg-secondary" id="queue-count">0</span>
      </button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link" id="tab-bans-btn" data-bs-toggle="tab" data-bs-target="#tab-bans" type="button" role="tab" aria-controls="tab-bans" aria-selected="false">
        <i class="bi bi-slash-circle"></i> Bans <span class="badge rounded-pill text-bg-secondary" id="ban-count">0</span>
      </button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link" id="tab-settings-btn" data-bs-toggle="tab" data-bs-target="#tab-settings" type="button" role="tab" aria-controls="tab-settings" aria-selected="false">
        <i class="bi bi-sliders"></i> Settings <span class="badge rounded-pill text-bg-warning d-none" id="settings-pending">restart</span>
      </button>
    </li>
    <li class="ms-auto align-self-center small text-body-secondary">
      <i class="bi bi-arrow-repeat"></i> <span id="updated-at">loading…</span>
    </li>
  </ul>

  <div class="tab-content">

    <!-- Overview -->
    <div class="tab-pane fade show active" id="tab-overview" role="tabpanel" aria-labelledby="tab-overview-btn" tabindex="0">
      <div class="row g-3 mb-4">
        <div class="col-sm-6 col-xl-3">
          <div class="card stat-card h-100"><div class="card-body">
            <div class="d-flex justify-content-between align-items-start">
              <div><div class="text-body-secondary small">Page slots in use</div><div class="stat-value" id="stat-occupancy">–</div></div>
              <i class="bi bi-door-open stat-icon text-primary"></i>
            </div>
            <div class="progress mt-3" role="progressbar" aria-label="Page slot utilization" aria-valuemin="0" aria-valuemax="100">
              <div class="progress-bar" id="bar-occupancy"></div>
            </div>
          </div></div>
        </div>
        <div class="col-sm-6 col-xl-3">
          <div class="card stat-card h-100"><div class="card-body">
            <div class="d-flex justify-content-between align-items-start">
              <div><div class="text-body-secondary small">Waiting in line</div><div class="stat-value" id="stat-queue">–</div></div>
              <i class="bi bi-hourglass-split stat-icon text-warning"></i>
            </div>
            <div class="small text-body-secondary mt-3">Ticket depth <span class="fw-semibold" id="stat-queue-depth">–</span> · max <span class="fw-semibold" data-stat="max_queue_depth">–</span></div>
          </div></div>
        </div>
        <div class="col-sm-6 col-xl-3">
          <div class="card stat-card h-100"><div class="card-body">
            <div class="d-flex justify-content-between align-items-start">
              <div><div class="text-body-secondary small">Asset slots in use</div><div class="stat-value" id="stat-assets">–</div></div>
              <i class="bi bi-images stat-icon text-info"></i>
            </div>
            <div class="progress mt-3" role="progressbar" aria-label="Asset slot utilization" aria-valuemin="0" aria-valuemax="100">
              <div class="progress-bar" id="bar-assets"></div>
            </div>
          </div></div>
        </div>
        <div class="col-sm-6 col-xl-3">
          <div class="card stat-card h-100"><div class="card-body">
            <div class="d-flex justify-content-between align-items-start">
              <div><div class="text-body-secondary small">Active bans</div><div class="stat-value" id="stat-bans">–</div></div>
              <i class="bi bi-shield-exclamation stat-icon text-danger"></i>
            </div>
            <div class="small text-body-secondary mt-3">Skip price <span class="fw-semibold" id="stat-price">–</span></div>
          </div></div>
        </div>
      </div>

      <div class="row g-3">
        <div class="col-lg-4">
          <div class="card stat-card h-100"><div class="card-body">
            <h2 class="h6 mb-3"><i class="bi bi-people"></i> Waiting room</h2>
            <dl class="row stat-list mb-0">
              <dt class="col-8">Visitors queued (total)</dt><dd class="col-4 text-end" data-stat="queued_total">–</dd>
              <dt class="col-8">Moved to the front</dt><dd class="col-4 text-end" data-stat="promoted_total">–</dd>
              <dt class="col-8">Abandoned tickets reaped</dt><dd class="col-4 text-end" data-stat="evicted_total">–</dd>
              <dt class="col-8">Gave up before admission</dt><dd class="col-4 text-end" data-stat="timeouts_total">–</dd>
              <dt class="col-8">Tracked in the portal</dt><dd class="col-4 text-end" data-stat="occupants_tracked">–</dd>
              <dt class="col-8">Removed, still blocked</dt><dd class="col-4 text-end" data-stat="kicked_active">–</dd>
            </dl>
          </div></div>
        </div>
        <div class="col-lg-4">
          <div class="card stat-card h-100"><div class="card-body">
            <h2 class="h6 mb-3"><i class="bi bi-images"></i> Asset tier</h2>
            <dl class="row stat-list mb-0">
              <dt class="col-8">Served</dt><dd class="col-4 text-end" data-stat="asset_served_total">–</dd>
              <dt class="col-8">Denied (no pass)</dt><dd class="col-4 text-end" data-stat="asset_denied_total">–</dd>
              <dt class="col-8">Per-user throttled</dt><dd class="col-4 text-end" data-stat="asset_user_throttled_total">–</dd>
              <dt class="col-8">Global throttled</dt><dd class="col-4 text-end" data-stat="asset_global_throttled_total">–</dd>
              <dt class="col-8">Active passes</dt><dd class="col-4 text-end" data-stat="asset_users">–</dd>
            </dl>
          </div></div>
        </div>
        <div class="col-lg-4">
          <div class="card stat-card h-100"><div class="card-body">
            <h2 class="h6 mb-3"><i class="bi bi-shield-exclamation"></i> Abuse registry</h2>
            <dl class="row stat-list mb-0">
              <dt class="col-8">Strikes recorded</dt><dd class="col-4 text-end" data-stat="abuse_strikes_total">–</dd>
              <dt class="col-8">Bans issued</dt><dd class="col-4 text-end" data-stat="abuse_bans_total">–</dd>
              <dt class="col-8">Requests blocked</dt><dd class="col-4 text-end" data-stat="abuse_rejected_total">–</dd>
              <dt class="col-8">Clients tracked</dt><dd class="col-4 text-end" data-stat="abuse_tracked">–</dd>
              <dt class="col-8">Range bans</dt><dd class="col-4 text-end" data-stat="abuse_range_bans">–</dd>
              <dt class="col-8">Dropped (table full)</dt><dd class="col-4 text-end" data-stat="abuse_dropped_total">–</dd>
            </dl>
          </div></div>
        </div>
      </div>
    </div>

    <!-- Queue -->
    <div class="tab-pane fade" id="tab-queue" role="tabpanel" aria-labelledby="tab-queue-btn" tabindex="0">
      <div class="d-flex flex-wrap align-items-center gap-2 mb-3">
        <div class="input-group input-group-sm filter-input">
          <span class="input-group-text"><i class="bi bi-search"></i></span>
          <input type="search" class="form-control" id="queue-filter" placeholder="Filter by address, path or browser" aria-label="Filter the queue">
        </div>
        <span class="small text-body-secondary" id="queue-summary"></span>
        <button type="button" class="btn btn-sm btn-outline-secondary ms-auto" id="queue-refresh"><i class="bi bi-arrow-clockwise"></i> Refresh</button>
      </div>
      <div class="card stat-card">
        <div class="table-responsive">
          <table class="table table-hover table-portal mb-0">
            <thead>
              <tr>
                <th scope="col">Position</th>
                <th scope="col">Client</th>
                <th scope="col">State</th>
                <th scope="col">Waiting</th>
                <th scope="col">Last seen</th>
                <th scope="col">Path</th>
                <th scope="col">Browser</th>
                <th scope="col" class="text-end">Actions</th>
              </tr>
            </thead>
            <tbody id="queue-rows"></tbody>
          </table>
        </div>
      </div>
      <p class="small text-body-secondary mt-3 mb-0">
        <i class="bi bi-info-circle"></i> Positions update when each visitor's browser polls, about every 3 seconds.
        Removing or banning a visitor takes them out of the line at once; banning also drops everyone else waiting from the same address or range.
      </p>
    </div>

    <!-- Bans -->
    <div class="tab-pane fade" id="tab-bans" role="tabpanel" aria-labelledby="tab-bans-btn" tabindex="0">
      <div class="alert alert-secondary d-none" id="bans-disabled" role="alert">
        <i class="bi bi-info-circle"></i> The abuse registry is disabled (<code>-abuse=false</code>), so bans are unavailable.
      </div>
      <div class="alert alert-warning d-none" id="bans-not-persisted" role="alert">
        <i class="bi bi-exclamation-triangle"></i> <code>-data-dir</code> is empty, so bans — including permanent ones — are lost when concert restarts.
      </div>
      <div class="d-flex align-items-center gap-2 mb-3">
        <button type="button" class="btn btn-sm btn-danger" id="ban-new"><i class="bi bi-plus-circle"></i> Ban a client or range</button>
        <button type="button" class="btn btn-sm btn-outline-secondary ms-auto" id="bans-refresh"><i class="bi bi-arrow-clockwise"></i> Refresh</button>
      </div>
      <div class="card stat-card">
        <div class="table-responsive">
          <table class="table table-hover table-portal mb-0">
            <thead>
              <tr>
                <th scope="col">Client</th>
                <th scope="col">Banned until</th>
                <th scope="col">Remaining</th>
                <th scope="col">Offenses</th>
                <th scope="col" class="text-end">Actions</th>
              </tr>
            </thead>
            <tbody id="ban-rows"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Settings -->
    <div class="tab-pane fade" id="tab-settings" role="tabpanel" aria-labelledby="tab-settings-btn" tabindex="0">
      <div class="alert alert-warning d-none" id="settings-restart" role="alert">
        <i class="bi bi-arrow-repeat"></i> Some saved settings take effect after a restart: <code>systemctl restart concert</code>.
      </div>
      <div class="row g-3">
        <div class="col-xl-8">
          <form id="settings-form" novalidate>
            <div class="d-flex flex-wrap align-items-center gap-2 mb-3">
              <div class="input-group input-group-sm filter-input">
                <span class="input-group-text"><i class="bi bi-search"></i></span>
                <input type="search" class="form-control" id="settings-filter" placeholder="Filter by name, flag or variable" aria-label="Filter settings">
              </div>
              <button type="button" class="btn btn-sm btn-outline-secondary ms-auto" id="settings-discard" disabled><i class="bi bi-x-circle"></i> Discard</button>
              <button type="submit" class="btn btn-sm btn-primary" id="settings-apply" disabled><i class="bi bi-check2-circle"></i> <span id="settings-apply-label">Save changes</span></button>
            </div>
            <div id="settings-groups" class="d-grid gap-3"></div>
          </form>
        </div>
        <div class="col-xl-4">
          <div class="card stat-card mb-3"><div class="card-body">
            <h2 class="h6 mb-3"><i class="bi bi-layers"></i> Where settings come from</h2>
            <p class="small mb-2">Each setting uses the first of these that has a value:</p>
            <ol class="small mb-3 ps-3">
              <li><span class="badge text-bg-success">saved</span> changed here, stored in settings.json</li>
              <li><span class="badge text-bg-primary">flag</span> command-line flag</li>
              <li><span class="badge text-bg-info">env</span> <code>CONCERT_*</code> environment variable</li>
              <li><span class="badge text-bg-light border">default</span> built-in default</li>
            </ol>
            <p class="small mb-2">
              <span class="badge bg-warning-subtle text-warning-emphasis border border-warning-subtle">restart</span>
              settings are saved at once and used from the next start. The rest apply immediately.
              Reset removes a value from settings.json.
            </p>
            <p class="small mb-0 text-break">File: <span class="font-monospace" id="settings-file">–</span></p>
          </div></div>
          <div class="card stat-card"><div class="card-body">
            <h2 class="h6 mb-3"><i class="bi bi-lock"></i> Environment only</h2>
            <dl class="row small mb-0" id="settings-fixed"></dl>
          </div></div>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- Ban create / edit -->
<div class="modal fade" id="ban-modal" tabindex="-1" aria-labelledby="ban-modal-title" aria-hidden="true">
  <div class="modal-dialog">
    <form class="modal-content" id="ban-form" novalidate>
      <div class="modal-header">
        <h2 class="modal-title fs-5" id="ban-modal-title">Ban a client</h2>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body">
        <div class="mb-3">
          <label for="ban-client" class="form-label">Client or range</label>
          <input type="text" class="form-control font-monospace" id="ban-client" required placeholder="203.0.113.9 · 203.0.0.0/16 · 2001:db8::/48">
          <div class="form-text">
            An address or a CIDR range. IPv6 addresses are banned by their /64.
            Ranges may be as broad as /8 for IPv4 and /16 for IPv6.
            Addresses in the abuse allowlist and trusted proxies stay reachable inside a banned range.
            Visitors waiting in line from the banned network are dropped immediately.
          </div>
        </div>
        <div class="form-check form-switch mb-3">
          <input class="form-check-input" type="checkbox" role="switch" id="ban-permanent">
          <label class="form-check-label" for="ban-permanent">Permanent — lasts until someone unbans it</label>
        </div>
        <fieldset id="ban-duration-group">
          <label for="ban-duration" class="form-label">Duration</label>
          <input type="text" class="form-control" id="ban-duration" required value="1h" placeholder="30m, 1h, 24h">
          <div class="d-flex flex-wrap gap-1 mt-2" id="ban-presets">
            <button type="button" class="btn btn-sm btn-outline-secondary" data-duration="15m">15m</button>
            <button type="button" class="btn btn-sm btn-outline-secondary" data-duration="1h">1h</button>
            <button type="button" class="btn btn-sm btn-outline-secondary" data-duration="6h">6h</button>
            <button type="button" class="btn btn-sm btn-outline-secondary" data-duration="24h">24h</button>
            <button type="button" class="btn btn-sm btn-outline-secondary" data-duration="168h">7 days</button>
            <button type="button" class="btn btn-sm btn-outline-secondary" data-duration="720h">30 days</button>
          </div>
        </fieldset>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
        <button type="submit" class="btn btn-danger"><i class="bi bi-slash-circle"></i> <span id="ban-submit-label">Ban</span></button>
      </div>
    </form>
  </div>
</div>
{{end}}
{{template "footer" .}}