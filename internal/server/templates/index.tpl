{{template "header" .}}
{{if not .Authed}}
<div class="row justify-content-center">
  <div class="col-sm-9 col-md-6 col-lg-4">
    <div class="card stat-card mt-5">
      <div class="card-body p-4">
        <h1 class="h4 mb-1"><i aria-hidden="true" class="bi bi-shield-lock"></i> Portal sign in</h1>
        <p class="text-body-secondary small mb-4">Enter the portal pass to manage this concert.</p>
        {{if .Error}}<div class="alert alert-danger py-2" role="alert"><i aria-hidden="true" class="bi bi-exclamation-triangle"></i> {{.Error}}</div>{{end}}
        <form method="post" action="/login" autocomplete="off">
          {{if .MultiUser}}
          <label for="user" class="form-label">Username</label>
          <input type="text" class="form-control mb-3" id="user" name="user" autocomplete="username" autofocus required>
          <label for="pass" class="form-label">Password</label>
          <input type="password" class="form-control mb-3" id="pass" name="pass" required>
          <label for="totp" class="form-label">MFA code <span class="text-body-secondary small">(if enabled)</span></label>
          <input type="text" inputmode="numeric" pattern="[0-9]*" maxlength="6" class="form-control mb-3" id="totp" name="totp" placeholder="6-digit TOTP">
          {{else}}
          <label for="pass" class="form-label">Portal pass</label>
          <input type="password" class="form-control mb-3" id="pass" name="pass" required autofocus>
          {{end}}
          <button type="submit" class="btn btn-primary w-100"><i aria-hidden="true" class="bi bi-box-arrow-in-right"></i> Sign in</button>
        </form>
      </div>
    </div>
  </div>
</div>
{{else}}
<div id="portal-app">
  <div class="alert alert-info d-none" id="portal-moved" role="alert"></div>

  <div class="card stat-card mb-3 d-none" id="vhost-bar">
    <div class="card-body py-2 px-3 d-flex flex-wrap align-items-center justify-content-between gap-2">
      <div class="d-flex flex-wrap align-items-center gap-2">
        <label for="site-selector" class="small fw-semibold mb-0"><i aria-hidden="true" class="bi bi-diagram-3"></i> Site</label>
        <select class="form-select form-select-sm w-auto" id="site-selector" aria-label="Select virtual host site"></select>
        <span class="badge text-bg-warning d-none" id="badge-runtime-override" title="Live cap override is temporary and resets on config reload">Temporary cap override</span>
      </div>
      <div class="d-flex flex-wrap align-items-center gap-3 small text-body-secondary">
        <span id="vhost-summary">–</span>
        <button type="button" class="btn btn-sm btn-outline-primary d-none" id="vhost-reload-btn"><i aria-hidden="true" class="bi bi-arrow-clockwise"></i> Reload config</button>
      </div>
    </div>
  </div>

  <ul class="nav nav-tabs mb-4" role="tablist">
    <li class="nav-item" role="presentation">
      <button class="nav-link active" id="tab-overview-btn" data-bs-toggle="tab" data-bs-target="#tab-overview" type="button" role="tab" aria-controls="tab-overview" aria-selected="true">
        <i aria-hidden="true" class="bi bi-speedometer2"></i> Overview
      </button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link" id="tab-queue-btn" data-bs-toggle="tab" data-bs-target="#tab-queue" type="button" role="tab" aria-controls="tab-queue" aria-selected="false">
        <i aria-hidden="true" class="bi bi-people"></i> Queue <span class="badge rounded-pill text-bg-secondary" id="queue-count">0</span>
      </button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link" id="tab-bans-btn" data-bs-toggle="tab" data-bs-target="#tab-bans" type="button" role="tab" aria-controls="tab-bans" aria-selected="false">
        <i aria-hidden="true" class="bi bi-slash-circle"></i> Bans <span class="badge rounded-pill text-bg-secondary" id="ban-count">0</span>
      </button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link" id="tab-visitors-btn" data-bs-toggle="tab" data-bs-target="#tab-visitors" type="button" role="tab" aria-controls="tab-visitors" aria-selected="false">
        <i aria-hidden="true" class="bi bi-person-lines-fill"></i> Visitors <span class="badge rounded-pill text-bg-secondary" id="visitors-count">0</span>
      </button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link" id="tab-banlog-btn" data-bs-toggle="tab" data-bs-target="#tab-banlog" type="button" role="tab" aria-controls="tab-banlog" aria-selected="false">
        <i aria-hidden="true" class="bi bi-shield-exclamation"></i> Ban log
      </button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link" id="tab-fastlane-btn" data-bs-toggle="tab" data-bs-target="#tab-fastlane" type="button" role="tab" aria-controls="tab-fastlane" aria-selected="false"><i aria-hidden="true" class="bi bi-lightning-charge"></i> Fast lane</button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link" id="tab-email-btn" data-bs-toggle="tab" data-bs-target="#tab-email" type="button" role="tab" aria-controls="tab-email" aria-selected="false">
        <i aria-hidden="true" class="bi bi-envelope-check"></i> Email <span class="badge rounded-pill text-bg-secondary" id="email-queue-count">0</span>
      </button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link" id="tab-settings-btn" data-bs-toggle="tab" data-bs-target="#tab-settings" type="button" role="tab" aria-controls="tab-settings" aria-selected="false">
        <i aria-hidden="true" class="bi bi-sliders"></i> Settings
      </button>
    </li>
    <li class="ms-auto align-self-center small text-body-secondary d-flex flex-wrap gap-3">
      <span title="Where IP details come from"><i aria-hidden="true" class="bi bi-globe2"></i> <span class="text-truncate d-inline-block ipinfo-state align-bottom">{{.IPInfo}}</span></span>
      <span><i aria-hidden="true" class="bi bi-arrow-repeat"></i> <span id="updated-at">loading…</span></span>
    </li>
  </ul>

  <div class="tab-content">
    <div class="tab-pane fade" id="tab-fastlane" role="tabpanel" aria-labelledby="tab-fastlane-btn" tabindex="0">
      <div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-3">
        <div>
          <p class="concert-eyebrow mb-1">X402 + MULTI-CHAIN FAST-LANE</p>
          <h2 class="h3 mb-0">Crypto Passes, NFTs &amp; Token Gates</h2>
        </div>
        <div class="d-flex flex-wrap align-items-center gap-2">
          <span class="badge d-none" id="fastlane-mode-badge"></span>
          <span class="badge d-none" id="fastlane-policy-badge"></span>
          <span class="badge text-bg-secondary d-none" id="fastlane-lock-badge"><i aria-hidden="true" class="bi bi-lock-fill"></i> Wallets Locked</span>
          <button class="btn btn-outline-info btn-sm" id="fastlane-refresh" type="button"><i aria-hidden="true" class="bi bi-arrow-repeat"></i> Refresh</button>
          <button class="btn btn-primary btn-sm d-none" id="fastlane-save-top" type="button"><i aria-hidden="true" class="bi bi-check2-circle"></i> Save &amp; Apply Live</button>
        </div>
      </div>

      <div id="fastlane-state" class="alert alert-info" role="status">Loading fast-lane configuration…</div>
      <div id="fastlane-save-feedback" class="alert d-none" role="status"></div>
      <div id="fastlane-capacity-alert" class="alert d-none" role="alert"></div>
      <div class="row g-3 mb-4" id="fastlane-stats"></div>

      <!-- Receipt Journal Headroom + Zero-Downtime Online Archival -->
      <div class="card stat-card mb-4 d-none" id="fastlane-headroom-card">
        <div class="card-body">
          <div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-2">
            <h3 class="h6 mb-0"><i aria-hidden="true" class="bi bi-journal-check"></i> Receipt journal headroom &amp; live archival</h3>
            <span class="small font-monospace" id="fastlane-headroom-text">–</span>
          </div>
          <div class="progress mb-2" role="progressbar" aria-label="Fast-lane receipt journal usage" aria-valuemin="0" aria-valuemax="100">
            <div class="progress-bar" id="fastlane-headroom-bar"></div>
          </div>
          <div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mt-2">
            <span class="small text-body-secondary">Alerts fire at 80% and 95%. Compact expired settled receipts live without downtime.</span>
            <div class="d-flex flex-wrap align-items-center gap-2">
              <select class="form-select form-select-sm w-auto" id="fastlane-archive-age" aria-label="Archive receipts older than">
                <option value="24h">Older than 24h</option>
                <option value="168h">Older than 7d</option>
                <option value="720h" selected>Older than 30d</option>
                <option value="2160h">Older than 90d</option>
              </select>
              <button class="btn btn-sm btn-outline-secondary" id="fastlane-archive-dry" type="button">Dry Run</button>
              <button class="btn btn-sm btn-outline-warning" id="fastlane-archive-run" type="button"><i aria-hidden="true" class="bi bi-archive"></i> Archive Live</button>
            </div>
          </div>
          <div class="small mt-2 d-none" id="fastlane-archive-status" role="status"></div>
        </div>
      </div>

      <!-- Optional Fee-Sponsor Balance Health -->
      <div class="card stat-card mb-4 d-none" id="fastlane-sponsor-card">
        <div class="card-body">
          <h3 class="h6 mb-2"><i aria-hidden="true" class="bi bi-fuel-pump"></i> Optional fee-sponsor accounts</h3>
          <div class="row g-2" id="fastlane-sponsor-rows"></div>
        </div>
      </div>

      <!-- Unresolved Receipts (Zero-Downtime Online Reconciliation) -->
      <div class="card stat-card mb-4 d-none" id="fastlane-unresolved-card">
        <div class="card-body">
          <div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-2">
            <h3 class="h6 mb-0"><i aria-hidden="true" class="bi bi-exclamation-octagon"></i> Unresolved receipts (zero-downtime online reconciliation)</h3>
            <span class="small text-body-secondary" id="fastlane-reconcile-status" role="status"></span>
          </div>
          <p class="small text-body-secondary mb-3">Reconciliation checks final on-chain state read-only without stopping Concert, signing, or moving funds. Once confirmed, the payer’s session unlocks immediately.</p>
          <div class="table-responsive">
            <table class="table table-sm table-hover align-middle mb-0">
              <thead>
                <tr>
                  <th scope="col">State</th>
                  <th scope="col">Network</th>
                  <th scope="col">Payer / Amount</th>
                  <th scope="col">Fingerprint</th>
                  <th scope="col">Started</th>
                  <th scope="col" class="text-end">Action</th>
                </tr>
              </thead>
              <tbody id="fastlane-unresolved-rows"></tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Live Fast-Lane Configuration Studio -->
      <div id="fastlane-editor" class="d-none">
        <!-- General, Policy Screening & Sliding Session Timing -->
        <div class="card stat-card mb-4">
          <div class="card-body">
            <h3 class="h5 mb-3"><i aria-hidden="true" class="bi bi-sliders2"></i> General, Mainnet Policy &amp; Pass Timing</h3>
            <div class="row g-3">
              <div class="col-md-3">
                <div class="form-check form-switch mt-2">
                  <input class="form-check-input" type="checkbox" id="fl-enabled">
                  <label class="form-check-label fw-semibold" for="fl-enabled">Fast-lane enabled</label>
                </div>
                <div class="form-check form-switch mt-2">
                  <input class="form-check-input" type="checkbox" id="fl-test-mode">
                  <label class="form-check-label" for="fl-test-mode">Testnet mode only</label>
                </div>
              </div>
              <div class="col-md-4">
                <label class="form-label small" for="fl-merchant">Merchant display name</label>
                <input class="form-control form-control-sm" id="fl-merchant" type="text">
              </div>
              <div class="col-md-5">
                <label class="form-label small" for="fl-origin">Public origin URL</label>
                <input class="form-control form-control-sm font-monospace" id="fl-origin" type="url" placeholder="https://shop.example.com">
              </div>
              <div class="col-md-4">
                <label class="form-label small" for="fl-terms-url">Terms URL</label>
                <input class="form-control form-control-sm font-monospace" id="fl-terms-url" type="url">
              </div>
              <div class="col-md-4">
                <label class="form-label small" for="fl-privacy-url">Privacy URL</label>
                <input class="form-control form-control-sm font-monospace" id="fl-privacy-url" type="url">
              </div>
              <div class="col-md-4">
                <label class="form-label small" for="fl-refund-url">Refund / support URL</label>
                <input class="form-control form-control-sm font-monospace" id="fl-refund-url" type="url">
              </div>
            </div>
            <hr class="my-3">
            <div class="row g-3 align-items-end">
              <div class="col-md-3">
                <label class="form-label small" for="fl-policy-mode">Mainnet screening policy</label>
                <select class="form-select form-select-sm" id="fl-policy-mode">
                  <option value="blocklist">Local Blocklist File (OFAC / Denylist)</option>
                  <option value="webhook">External Screening Webhook</option>
                  <option value="none">None (Explicit Operator Opt-In)</option>
                </select>
              </div>
              <div class="col-md-5" id="fl-policy-url-wrap">
                <label class="form-label small" for="fl-policy-url">Policy webhook URL (HTTPS)</label>
                <input class="form-control form-control-sm font-monospace" id="fl-policy-url" type="url" placeholder="https://compliance.internal/screen">
              </div>
              <div class="col-md-5 d-none" id="fl-policy-file-wrap">
                <label class="form-label small" for="fl-policy-file">Local blocklist file path</label>
                <input class="form-control form-control-sm font-monospace" id="fl-policy-file" type="text" placeholder="/etc/concert/blocklist.txt">
              </div>
              <div class="col-md-4">
                <div class="form-check mt-2" id="fl-unscreened-wrap">
                  <input class="form-check-input" type="checkbox" id="fl-allow-unscreened">
                  <label class="form-check-label small" for="fl-allow-unscreened">Allow unscreened mainnet (override hardened guard)</label>
                </div>
              </div>
            </div>
            <hr class="my-3">
            <div class="row g-3 align-items-end">
              <div class="col-6 col-md-2">
                <label class="form-label small" for="fl-pass-secs">Initial pass (s)</label>
                <input class="form-control form-control-sm" id="fl-pass-secs" type="number" min="30" max="86400">
              </div>
              <div class="col-6 col-md-2">
                <label class="form-label small" for="fl-pass-idle">Sliding idle (s)</label>
                <input class="form-control form-control-sm" id="fl-pass-idle" type="number" min="30" max="86400">
              </div>
              <div class="col-6 col-md-2">
                <label class="form-label small" for="fl-pass-max">Hard max cap (s)</label>
                <input class="form-control form-control-sm" id="fl-pass-max" type="number" min="60" max="86400">
              </div>
              <div class="col-6 col-md-2">
                <label class="form-label small" for="fl-nft-secs">NFT / token lease (s)</label>
                <input class="form-control form-control-sm" id="fl-nft-secs" type="number" min="30" max="3600">
              </div>
              <div class="col-md-4">
                <div class="form-check form-switch">
                  <input class="form-check-input" type="checkbox" id="fl-pass-sliding">
                  <label class="form-check-label small" for="fl-pass-sliding">Sliding pass (keeps active browsers &amp; 45s+ PHP checkouts admitted)</label>
                </div>
                <div class="form-check form-switch mt-1">
                  <input class="form-check-input" type="checkbox" id="fl-direct-pay">
                  <label class="form-check-label small" for="fl-direct-pay">Direct QR + Destination Tag / Memo wallet flow</label>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Paid Pass Offers Editor with Multi-Chain Presets -->
        <div class="card stat-card mb-4">
          <div class="card-body">
            <div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-3">
              <div>
                <h3 class="h5 mb-0"><i aria-hidden="true" class="bi bi-coin"></i> Paid Fast-Lane Passes</h3>
                <div class="small text-body-secondary">Choose any combination of XRP/RLUSD, XLM/USDC, SOL/USDC, or HBAR/HTS tokens. Payer pays network fees by default (zero hot keys).</div>
              </div>
              <div class="d-flex flex-wrap gap-1" id="fl-offer-presets">
                <button class="btn btn-sm btn-outline-primary" type="button" data-preset="xrpl-rlusd">+ XRPL RLUSD</button>
                <button class="btn btn-sm btn-outline-primary" type="button" data-preset="xrpl-xrp">+ XRP</button>
                <button class="btn btn-sm btn-outline-info" type="button" data-preset="stellar-usdc">+ Stellar USDC</button>
                <button class="btn btn-sm btn-outline-info" type="button" data-preset="stellar-xlm">+ XLM</button>
                <button class="btn btn-sm btn-outline-success" type="button" data-preset="solana-usdc">+ Solana USDC</button>
                <button class="btn btn-sm btn-outline-success" type="button" data-preset="solana-sol">+ SOL</button>
                <button class="btn btn-sm btn-outline-warning" type="button" data-preset="hedera-usdc">+ Hedera USDC</button>
                <button class="btn btn-sm btn-outline-warning" type="button" data-preset="hedera-hbar">+ HBAR</button>
              </div>
            </div>
            <div id="fastlane-offers" class="d-flex flex-column gap-3"></div>
          </div>
        </div>

        <!-- NFT Collection Rules & Token/Trustline Balance Rules -->
        <div class="row g-4 mb-4">
          <section class="col-lg-6">
            <div class="card stat-card h-100">
              <div class="card-body">
                <div class="d-flex justify-content-between align-items-center gap-2 mb-3">
                  <div>
                    <h3 class="h5 mb-0"><i aria-hidden="true" class="bi bi-gem"></i> NFT Collection Rules</h3>
                    <div class="small text-body-secondary">Grant free entry, require holding before purchasing a pass, or both.</div>
                  </div>
                  <button class="btn btn-sm btn-outline-primary" id="fl-add-collection" type="button">+ Add NFT Rule</button>
                </div>
                <div id="fastlane-collections" class="d-flex flex-column gap-3"></div>
              </div>
            </div>
          </section>
          <section class="col-lg-6">
            <div class="card stat-card h-100">
              <div class="card-body">
                <div class="d-flex justify-content-between align-items-center gap-2 mb-3">
                  <div>
                    <h3 class="h5 mb-0"><i aria-hidden="true" class="bi bi-wallet2"></i> Token &amp; Trustline Balance Rules</h3>
                    <div class="small text-body-secondary">Require holding a minimum token balance (e.g. 10 RLUSD or 100 USDC) to enter or buy.</div>
                  </div>
                  <button class="btn btn-sm btn-outline-primary" id="fl-add-token-gate" type="button">+ Add Token Rule</button>
                </div>
                <div id="fastlane-token-gates" class="d-flex flex-column gap-3"></div>
              </div>
            </div>
          </section>
        </div>

        <!-- Optional Verification Receiving Addresses + Live Save Bar -->
        <div class="card stat-card mb-4">
          <div class="card-body">
            <div class="row g-3 align-items-end">
              <div class="col-lg-8">
                <h3 class="h6 mb-1"><i aria-hidden="true" class="bi bi-qr-code-scan"></i> 1-Drop / Memo Ownership Proof Receiving Wallets (Optional)</h3>
                <p class="small text-body-secondary mb-2">Defaults to the matching paid offer’s receiving wallet. Set here only if you run free NFT/Token gates without a paid offer on that chain.</p>
                <div class="row g-2">
                  <div class="col-md-6"><input class="form-control form-control-sm font-monospace" id="fl-verify-xrpl" placeholder="XRPL verify address (r...)"></div>
                  <div class="col-md-6"><input class="form-control form-control-sm font-monospace" id="fl-verify-stellar" placeholder="Stellar verify address (G...)"></div>
                  <div class="col-md-6"><input class="form-control form-control-sm font-monospace" id="fl-verify-solana" placeholder="Solana verify address (base58)"></div>
                  <div class="col-md-6"><input class="form-control form-control-sm font-monospace" id="fl-verify-hedera" placeholder="Hedera verify account (0.0.N)"></div>
                </div>
              </div>
              <div class="col-lg-4">
                <div class="d-none mb-2" id="fl-mfa-wrap">
                  <label class="form-label small text-warning mb-1" for="fl-mfa-code">TOTP MFA code (required to change receiving wallets in hardened mode)</label>
                  <input class="form-control form-control-sm font-monospace" id="fl-mfa-code" type="text" inputmode="numeric" autocomplete="one-time-code" placeholder="6-digit code">
                </div>
                <button class="btn btn-primary w-100" id="fastlane-save-bottom" type="button"><i aria-hidden="true" class="bi bi-check2-circle"></i> Save &amp; Apply Live (Zero Downtime)</button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Live Pass / Session Revocation -->
      <div class="card stat-card mb-4 d-none" id="fastlane-revoke-card">
        <div class="card-body">
          <div class="row g-2 align-items-end">
            <div class="col-md-8">
              <label class="form-label small fw-semibold mb-1" for="fastlane-revoke-target"><i aria-hidden="true" class="bi bi-slash-circle"></i> Revoke an active fast-lane session or pass ID immediately</label>
              <input class="form-control form-control-sm font-monospace" id="fastlane-revoke-target" type="text" placeholder="Session ID or Pass ID (propagates across Redis edges)">
            </div>
            <div class="col-md-4">
              <button class="btn btn-sm btn-outline-danger w-100" id="fastlane-revoke-btn" type="button">Revoke Pass Live</button>
            </div>
          </div>
          <div class="small mt-2 d-none" id="fastlane-revoke-status" role="status"></div>
        </div>
      </div>

      <div class="card mt-3" id="fastlane-help-card"><div class="card-body"><h3 class="h6">Multi-chain fast-lane setup</h3><p class="small text-body-secondary mb-0">Start <code>econcert</code> with <code>-fastlane-config</code> (or <code>fastlane_config</code> in <code>Concertfile</code>) and <code>-networks-config</code>. Live edits apply immediately with zero downtime, persist atomically (<code>0600</code>), write to the hash-chained audit log, and trigger a Critical email alert whenever receiving wallets change.</p></div></div>
    </div>

    <!-- Overview -->
    <div class="tab-pane fade show active" id="tab-overview" role="tabpanel" aria-labelledby="tab-overview-btn" tabindex="0">
      <div class="row g-3 mb-4">
        <div class="col-sm-6 col-xl-3">
          <div class="card stat-card h-100"><div class="card-body">
            <div class="d-flex justify-content-between align-items-start">
              <div><div class="text-body-secondary small">Page slots in use <span class="badge text-bg-warning ms-1 d-none" id="badge-cap-draining">draining</span></div><div class="stat-value" id="stat-occupancy">–</div></div>
              <i aria-hidden="true" class="bi bi-door-open stat-icon text-primary"></i>
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
              <i aria-hidden="true" class="bi bi-hourglass-split stat-icon text-warning"></i>
            </div>
            <div class="small text-body-secondary mt-3">Ticket depth <span class="fw-semibold" id="stat-queue-depth">–</span> · max <span class="fw-semibold" data-stat="max_queue_depth">–</span></div>
          </div></div>
        </div>
        <div class="col-sm-6 col-xl-3">
          <div class="card stat-card h-100"><div class="card-body">
            <div class="d-flex justify-content-between align-items-start">
              <div><div class="text-body-secondary small">Asset slots in use</div><div class="stat-value" id="stat-assets">–</div></div>
              <i aria-hidden="true" class="bi bi-images stat-icon text-info"></i>
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
              <i aria-hidden="true" class="bi bi-shield-exclamation stat-icon text-danger"></i>
            </div>
            <div class="small text-body-secondary mt-3">Skip price <span class="fw-semibold" id="stat-price">–</span></div>
          </div></div>
        </div>
      </div>

      <div class="row g-3">
        <div class="col-lg-4">
          <div class="card stat-card h-100"><div class="card-body">
            <h2 class="h6 mb-3"><i aria-hidden="true" class="bi bi-people"></i> Waiting room</h2>
            <dl class="row stat-list mb-0">
              <dt class="col-8">Visitors queued (total)</dt><dd class="col-4 text-end" data-stat="queued_total">–</dd>
              <dt class="col-8">Moved to the front</dt><dd class="col-4 text-end" data-stat="promoted_total">–</dd>
              <dt class="col-8">Abandoned tickets reaped</dt><dd class="col-4 text-end" data-stat="evicted_total">–</dd>
              <dt class="col-8">Gave up before admission</dt><dd class="col-4 text-end" data-stat="timeouts_total">–</dd>
              <dt class="col-8">Queue full rejections (503)</dt><dd class="col-4 text-end" data-stat="rejected_503_total">–</dd>
              <dt class="col-8">Removed by bans and admins</dt><dd class="col-4 text-end" data-stat="removed_total">–</dd>
              <dt class="col-8">Removed, still blocked</dt><dd class="col-4 text-end" data-stat="kicked_active">–</dd>
            </dl>
          </div></div>
        </div>
        <div class="col-lg-4">
          <div class="card stat-card h-100"><div class="card-body">
            <h2 class="h6 mb-3"><i aria-hidden="true" class="bi bi-images"></i> Assets and streams</h2>
            <dl class="row stat-list mb-0">
              <dt class="col-8">Assets served</dt><dd class="col-4 text-end" data-stat="asset_served_total">–</dd>
              <dt class="col-8">Assets denied (no pass)</dt><dd class="col-4 text-end" data-stat="asset_denied_total">–</dd>
              <dt class="col-8">Per-user throttled</dt><dd class="col-4 text-end" data-stat="asset_user_throttled_total">–</dd>
              <dt class="col-8">Global throttled</dt><dd class="col-4 text-end" data-stat="asset_global_throttled_total">–</dd>
              <dt class="col-8">Active passes</dt><dd class="col-4 text-end" data-stat="asset_users">–</dd>
              <dt class="col-8">Streams open</dt><dd class="col-4 text-end" id="stat-streams">–</dd>
              <dt class="col-8">Streams refused (full)</dt><dd class="col-4 text-end" data-stat="stream_throttled_total">–</dd>
              <dt class="col-8">Streams denied (no pass)</dt><dd class="col-4 text-end" data-stat="stream_denied_total">–</dd>
            </dl>
          </div></div>
        </div>
        <div class="col-lg-4">
          <div class="card stat-card h-100"><div class="card-body">
            <h2 class="h6 mb-3"><i aria-hidden="true" class="bi bi-shield-exclamation"></i> Abuse registry</h2>
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

        <!-- Priority: wraps onto its own line inside the same row. -->
        <div class="col-lg-4">
          <div class="card stat-card h-100"><div class="card-body">
            <h2 class="h6 mb-3"><i aria-hidden="true" class="bi bi-stars"></i> Priority lane</h2>
            <dl class="row stat-list mb-0">
              <dt class="col-8">Lane slots in use</dt><dd class="col-4 text-end" data-stat="priority_lane_in_flight">–</dd>
              <dt class="col-8">Lane slots</dt><dd class="col-4 text-end" data-stat="priority_lane_cap">–</dd>
              <dt class="col-8">Waiting for a lane slot</dt><dd class="col-4 text-end" data-stat="priority_lane_waiting">–</dd>
              <dt class="col-8">Served through the lane</dt><dd class="col-4 text-end" data-stat="priority_lane_served_total">–</dd>
              <dt class="col-8">Lane full, joined the line</dt><dd class="col-4 text-end" data-stat="priority_lane_full_total">–</dd>
              <dt class="col-8">Moved up the line by rank</dt><dd class="col-4 text-end" data-stat="priority_placed_total">–</dd>
            </dl>
          </div></div>
        </div>
        <div class="col-lg-4">
          <div class="card stat-card h-100"><div class="card-body">
            <h2 class="h6 mb-3"><i aria-hidden="true" class="bi bi-patch-check"></i> Grants and forms</h2>
            <dl class="row stat-list mb-0">
              <dt class="col-8">Grants issued by the app</dt><dd class="col-4 text-end" data-stat="priority_grants_total">–</dd>
              <dt class="col-8">Grants cleared (guest)</dt><dd class="col-4 text-end" data-stat="priority_grants_cleared_total">–</dd>
              <dt class="col-8">Headers ignored (unknown)</dt><dd class="col-4 text-end" data-stat="priority_grants_rejected_total">–</dd>
              <dt class="col-8">Forms that skipped the line</dt><dd class="col-4 text-end" data-stat="priority_forms_total">–</dd>
              <dt class="col-8">Forms refused (lane full)</dt><dd class="col-4 text-end" data-stat="priority_forms_refused_total">–</dd>
            </dl>
          </div></div>
        </div>
        <div class="col-lg-4">
          <div class="card stat-card h-100"><div class="card-body">
            <h2 class="h6 mb-3"><i aria-hidden="true" class="bi bi-bar-chart-steps"></i> Page requests by rank</h2>
            <dl class="row stat-list mb-0">
              <dt class="col-8">Staff</dt><dd class="col-4 text-end" data-stat="priority_requests_staff">–</dd>
              <dt class="col-8">Checkout</dt><dd class="col-4 text-end" data-stat="priority_requests_checkout">–</dd>
              <dt class="col-8">Subscriber</dt><dd class="col-4 text-end" data-stat="priority_requests_subscriber">–</dd>
              <dt class="col-8">Customer</dt><dd class="col-4 text-end" data-stat="priority_requests_customer">–</dd>
              <dt class="col-8">Prospect</dt><dd class="col-4 text-end" data-stat="priority_requests_prospect">–</dd>
              <dt class="col-8">Member</dt><dd class="col-4 text-end" data-stat="priority_requests_member">–</dd>
              <dt class="col-8">Guest</dt><dd class="col-4 text-end" data-stat="priority_requests_guest">–</dd>
            </dl>
          </div></div>
        </div>
      </div>

      <!-- Edge / Leaf tier observability & on-demand re-benchmarking (T6) -->
      <div class="mt-4 d-none" id="tier-section">
        <div class="d-flex flex-wrap align-items-center justify-content-between gap-2 mb-3">
          <div class="d-flex align-items-center gap-2">
            <h2 class="h5 mb-0"><i aria-hidden="true" class="bi bi-diagram-3"></i> Tier &amp; capacity</h2>
            <span class="badge text-bg-primary text-uppercase" id="tier-role-badge"></span>
            <span class="font-monospace small text-body-secondary" id="tier-node-id"></span>
          </div>
          <button type="button" class="btn btn-sm btn-outline-primary d-none" id="tier-leaf-rebench-btn">
            <i aria-hidden="true" class="bi bi-speedometer"></i> Drain &amp; re-benchmark
          </button>
        </div>

        <!-- Edge view -->
        <div class="d-none" id="tier-edge-view">
          <div class="row g-3 mb-3">
            <div class="col-md-4">
              <div class="card stat-card h-100"><div class="card-body">
                <h3 class="h6 mb-2"><i aria-hidden="true" class="bi bi-hdd-network"></i> Edge capacity plan</h3>
                <dl class="row stat-list mb-0">
                  <dt class="col-8">Usable leaves</dt><dd class="col-4 text-end" id="edge-leaves-usable">–</dd>
                  <dt class="col-8">Leaf page slots</dt><dd class="col-4 text-end" id="edge-leaf-slots">–</dd>
                  <dt class="col-8">Planned room cap</dt><dd class="col-4 text-end" id="edge-planned-cap">–</dd>
                </dl>
              </div></div>
            </div>
            <div class="col-md-4">
              <div class="card stat-card h-100"><div class="card-body">
                <h3 class="h6 mb-2"><i aria-hidden="true" class="bi bi-arrow-left-right"></i> Data plane</h3>
                <dl class="row stat-list mb-0">
                  <dt class="col-8">Leaf backpressure (503)</dt><dd class="col-4 text-end" id="edge-backpressure">–</dd>
                  <dt class="col-8">Upstream retries</dt><dd class="col-4 text-end" id="edge-retries">–</dd>
                </dl>
              </div></div>
            </div>
            <div class="col-md-4">
              <div class="card stat-card h-100"><div class="card-body">
                <h3 class="h6 mb-2"><i aria-hidden="true" class="bi bi-broadcast"></i> Control plane</h3>
                <dl class="row stat-list mb-0">
                  <dt class="col-8">Leaf polls (errors)</dt><dd class="col-4 text-end" id="edge-polls">–</dd>
                  <dt class="col-8">Ban pushes (errors)</dt><dd class="col-4 text-end" id="edge-pushes">–</dd>
                </dl>
              </div></div>
            </div>
          </div>
          <div class="card stat-card">
            <div class="card-body p-0">
              <div class="table-responsive">
                <table class="table table-sm table-hover align-middle mb-0">
                  <thead>
                    <tr>
                      <th>Leaf</th>
                      <th>Status</th>
                      <th class="text-end">Host cap</th>
                      <th class="text-end">Weighted share</th>
                      <th class="text-end">In flight</th>
                      <th class="text-end">Latency</th>
                      <th>Last silence / benchmark</th>
                      <th class="text-end">Action</th>
                    </tr>
                  </thead>
                  <tbody id="tier-edge-leaves"></tbody>
                </table>
              </div>
            </div>
          </div>
        </div>

        <!-- Leaf view -->
        <div class="d-none" id="tier-leaf-view">
          <div class="alert alert-danger d-none mb-3" id="tier-leaf-silence" role="alert"></div>
          <div class="row g-3">
            <div class="col-lg-4">
              <div class="card stat-card h-100"><div class="card-body">
                <h3 class="h6 mb-2"><i aria-hidden="true" class="bi bi-cpu"></i> Host gate</h3>
                <dl class="row stat-list mb-0">
                  <dt class="col-7">Host cap</dt><dd class="col-5 text-end" id="leaf-host-cap">–</dd>
                  <dt class="col-7">Hop in flight (waiting)</dt><dd class="col-5 text-end" id="leaf-hop-inflight">–</dd>
                  <dt class="col-7">Direct in flight (waiting)</dt><dd class="col-5 text-end" id="leaf-direct-inflight">–</dd>
                  <dt class="col-7">Mean latency</dt><dd class="col-5 text-end" id="leaf-latency">–</dd>
                </dl>
              </div></div>
            </div>
            <div class="col-lg-4">
              <div class="card stat-card h-100"><div class="card-body">
                <h3 class="h6 mb-2"><i aria-hidden="true" class="bi bi-shield-check"></i> Trust chain</h3>
                <dl class="row stat-list mb-0">
                  <dt class="col-8">Verified hop claims</dt><dd class="col-4 text-end" id="leaf-hop-accepted">–</dd>
                  <dt class="col-8">Rejected claims</dt><dd class="col-4 text-end" id="leaf-hop-rejected">–</dd>
                  <dt class="col-8">Replayed nonces blocked</dt><dd class="col-4 text-end" id="leaf-hop-replayed">–</dd>
                  <dt class="col-8">Missing mTLS rejected</dt><dd class="col-4 text-end" id="leaf-hop-mtls">–</dd>
                  <dt class="col-8">Backpressure refusals</dt><dd class="col-4 text-end" id="leaf-hop-backpressure">–</dd>
                </dl>
              </div></div>
            </div>
            <div class="col-lg-4">
              <div class="card stat-card h-100"><div class="card-body">
                <h3 class="h6 mb-2"><i aria-hidden="true" class="bi bi-bar-chart-line"></i> Edge shares &amp; benchmark</h3>
                <div class="small text-body-secondary mb-2" id="leaf-bench-summary">No benchmark recorded yet.</div>
                <ul class="list-group list-group-flush small" id="leaf-edge-shares"></ul>
              </div></div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Queue -->
    <div class="tab-pane fade" id="tab-queue" role="tabpanel" aria-labelledby="tab-queue-btn" tabindex="0">
      <div class="d-flex flex-wrap align-items-center gap-3 mb-3">
        <div class="input-group input-group-sm filter-input">
          <span class="input-group-text"><i aria-hidden="true" class="bi bi-search"></i></span>
          <input type="search" class="form-control" id="queue-filter" placeholder="Filter by address, path or browser" aria-label="Filter the queue">
        </div>
        <div class="form-check form-switch mb-0">
          <input class="form-check-input" type="checkbox" role="switch" id="queue-live" checked>
          <label class="form-check-label small" for="queue-live">Live</label>
        </div>
        <div class="ms-auto d-flex flex-wrap align-items-center gap-2">
          <button type="button" class="btn btn-sm btn-outline-warning" id="queue-clear-stale" title="Evict idle/abandoned tickets older than idle_poll_ttl (default 30s)"><i aria-hidden="true" class="bi bi-eraser"></i> Flush stale</button>
          <button type="button" class="btn btn-sm btn-outline-danger" id="queue-clear-all" title="Clear every waiting ticket from the queue immediately"><i aria-hidden="true" class="bi bi-trash"></i> Clear queue</button>
          <button type="button" class="btn btn-sm btn-outline-secondary" id="queue-refresh"><i aria-hidden="true" class="bi bi-arrow-clockwise"></i> Refresh</button>
        </div>
      </div>
      <div class="card stat-card">
        <div class="table-responsive">
          <table class="table table-hover table-portal live-table mb-0">
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
        <div class="card-footer live-footer d-flex flex-wrap align-items-center gap-2">
          <span class="badge live-state"></span>
          <span class="small text-body-secondary" id="queue-summary"></span>
          <div class="ms-auto" id="queue-pager"></div>
        </div>
      </div>
      <p class="small text-body-secondary mt-3 mb-0">
        <i aria-hidden="true" class="bi bi-info-circle"></i> Positions come straight from the waiting room; the table pages through the front of the line.
        Removing or banning a visitor takes them out of the line at once; banning also drops everyone else waiting from the same address or range.
        Live updates pause while the pointer is over the table.
      </p>
    </div>

    <!-- Bans -->
    <div class="tab-pane fade" id="tab-bans" role="tabpanel" aria-labelledby="tab-bans-btn" tabindex="0">
      <div class="alert alert-secondary d-none" id="bans-disabled" role="alert">
        <i aria-hidden="true" class="bi bi-info-circle"></i> The abuse registry is off (<code>abuse</code> in Settings). Existing bans are kept and apply again when it is turned back on.
      </div>
      <div class="alert alert-warning d-none" id="bans-not-persisted" role="alert">
        <i aria-hidden="true" class="bi bi-exclamation-triangle"></i> <code>-data-dir</code> is empty, so bans — including permanent ones — are lost when concert restarts.
      </div>
      <div class="d-flex flex-wrap align-items-center gap-3 mb-3">
        <button type="button" class="btn btn-sm btn-danger" id="ban-new"><i aria-hidden="true" class="bi bi-plus-circle"></i> Ban a client or range</button>
        <div class="form-check form-switch mb-0">
          <input class="form-check-input" type="checkbox" role="switch" id="bans-live" checked>
          <label class="form-check-label small" for="bans-live">Live</label>
        </div>
        <button type="button" class="btn btn-sm btn-outline-secondary ms-auto" id="bans-refresh"><i aria-hidden="true" class="bi bi-arrow-clockwise"></i> Refresh</button>
      </div>
      <div class="card stat-card">
        <div class="table-responsive">
          <table class="table table-hover table-portal live-table mb-0">
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
        <div class="card-footer live-footer d-flex flex-wrap align-items-center gap-2">
          <span class="badge live-state"></span>
          <span class="small text-body-secondary" id="bans-summary"></span>
          <div class="ms-auto" id="bans-pager"></div>
        </div>
      </div>
    </div>

    <!-- Visitors -->
    <div class="tab-pane fade" id="tab-visitors" role="tabpanel" aria-labelledby="tab-visitors-btn" tabindex="0">
      <div class="d-flex flex-wrap align-items-center gap-3 mb-3">
        <div class="input-group input-group-sm filter-input">
          <span class="input-group-text"><i aria-hidden="true" class="bi bi-search"></i></span>
          <input type="search" class="form-control" id="visitors-filter" placeholder="Filter by address or path, e.g. /.env" aria-label="Filter visitors">
        </div>
        <div class="form-check form-switch mb-0">
          <input class="form-check-input" type="checkbox" role="switch" id="visitors-flagged">
          <label class="form-check-label small" for="visitors-flagged">Only clients that are or were banned</label>
        </div>
        <div class="form-check form-switch mb-0">
          <input class="form-check-input" type="checkbox" role="switch" id="visitors-live" checked>
          <label class="form-check-label small" for="visitors-live">Live</label>
        </div>
        <button type="button" class="btn btn-sm btn-outline-secondary ms-auto" id="visitors-refresh"><i aria-hidden="true" class="bi bi-arrow-clockwise"></i> Refresh</button>
      </div>
      <div class="card stat-card">
        <div class="table-responsive">
          <table class="table table-hover table-portal live-table mb-0">
            <thead>
              <tr>
                <th scope="col" class="history-toggle"><span class="visually-hidden">Details</span></th>
                <th scope="col">Client</th>
                <th scope="col">State</th>
                <th scope="col">Requests</th>
                <th scope="col">Blocked</th>
                <th scope="col">Errors</th>
                <th scope="col">Last seen</th>
                <th scope="col">Last request</th>
                <th scope="col" class="text-end">Actions</th>
              </tr>
            </thead>
            <tbody id="visitors-rows"></tbody>
          </table>
        </div>
        <div class="card-footer live-footer d-flex flex-wrap align-items-center gap-2">
          <span class="badge live-state"></span>
          <span class="small text-body-secondary" id="visitors-summary"></span>
          <div class="ms-auto" id="visitors-pager"></div>
        </div>
      </div>
      <p class="small text-body-secondary mt-3 mb-0"><i aria-hidden="true" class="bi bi-info-circle"></i> {{.HistoryNote}}
        Rows are tinted red for a permanent ban, amber for a temporary one, green when the last response was 2xx and blue otherwise.
        Hover the 4, 6 and 8 badges for an address in each form; click one to copy it.</p>
    </div>

    <!-- Ban log -->
    <div class="tab-pane fade" id="tab-banlog" role="tabpanel" aria-labelledby="tab-banlog-btn" tabindex="0">
      <div class="d-flex flex-wrap align-items-center gap-3 mb-3">
        <div class="input-group input-group-sm filter-input">
          <span class="input-group-text"><i aria-hidden="true" class="bi bi-search"></i></span>
          <input type="search" class="form-control" id="banlog-filter" placeholder="Filter by address or path" aria-label="Filter the ban log">
        </div>
        <div class="form-check form-switch mb-0">
          <input class="form-check-input" type="checkbox" role="switch" id="banlog-live" checked>
          <label class="form-check-label small" for="banlog-live">Live</label>
        </div>
        <button type="button" class="btn btn-sm btn-outline-secondary ms-auto" id="banlog-refresh"><i aria-hidden="true" class="bi bi-arrow-clockwise"></i> Refresh</button>
      </div>
      <div class="card stat-card">
        <div class="card-body pb-2">
          <p class="small text-body-secondary mb-0">Every ban in the history: when it began and ends, the request that started it, and everything the banned network requested while it was blocked. Expand a ban for every path and address.</p>
        </div>
        <div class="table-responsive">
          <table class="table table-hover table-portal live-table mb-0">
            <thead>
              <tr>
                <th scope="col" class="history-toggle"><span class="visually-hidden">Details</span></th>
                <th scope="col">Banned</th>
                <th scope="col">State</th>
                <th scope="col">Began</th>
                <th scope="col">Ends</th>
                <th scope="col"><attr title="Requests During Ban">RDB</attr></th>
                <th scope="col"><attr title="paths Hit While Banned">HWB</attr></th>
                <th scope="col">Started by</th>
              </tr>
            </thead>
            <tbody id="banlog-rows"></tbody>
          </table>
        </div>
        <div class="card-footer live-footer d-flex flex-wrap align-items-center gap-2">
          <span class="badge live-state"></span>
          <span class="small text-body-secondary" id="banlog-summary"></span>
          <div class="ms-auto" id="banlog-pager"></div>
        </div>
      </div>
    </div>

    <!-- Settings: section navigation | settings (info above input) | sources and fixed values -->
    <div class="tab-pane fade" id="tab-settings" role="tabpanel" aria-labelledby="tab-settings-btn" tabindex="0">
      <div class="alert alert-warning d-none" id="settings-unsaved" role="alert">
        <i aria-hidden="true" class="bi bi-exclamation-triangle"></i> <code>-data-dir</code> is empty: changes apply immediately but are lost when concert restarts.
      </div>
      <div class="row g-3">
        <div class="col-xl-2">
          <nav class="settings-nav nav nav-pills flex-row flex-xl-column gap-1" id="settings-nav" aria-label="Setting sections"></nav>
        </div>
        <div class="col-xl-6">
          <form id="settings-form" novalidate>
            <div class="d-flex flex-wrap align-items-center gap-2 mb-3">
              <div class="input-group input-group-sm filter-input">
                <span class="input-group-text"><i aria-hidden="true" class="bi bi-search"></i></span>
                <input type="search" class="form-control" id="settings-filter" placeholder="Filter by name, flag or variable" aria-label="Filter settings">
              </div>
              <button type="button" class="btn btn-sm btn-outline-secondary ms-auto" id="settings-discard" disabled><i aria-hidden="true" class="bi bi-x-circle"></i> Discard</button>
              <button type="submit" class="btn btn-sm btn-primary" id="settings-apply" disabled><i aria-hidden="true" class="bi bi-check2-circle"></i> <span id="settings-apply-label">Save changes</span></button>
            </div>
            <div id="settings-groups" class="d-grid gap-3"></div>
          </form>
        </div>
        <div class="col-xl-4">
          <div class="card stat-card mb-3"><div class="card-body">
            <h2 class="h6 mb-3"><i aria-hidden="true" class="bi bi-layers"></i> Where settings come from</h2>
            <p class="small mb-2">Each setting uses the first of these that has a value:</p>
            <ol class="small mb-3 ps-3">
              <li><span class="badge text-bg-success">saved</span> changed here, stored in settings.json</li>
              <li><span class="badge text-bg-primary">flag</span> command-line flag</li>
              <li><span class="badge text-bg-info">env</span> <code>CONCERT_*</code> environment variable</li>
              <li><span class="badge text-bg-light border">default</span> built-in default</li>
            </ol>
            <p class="small mb-2">
              Every change applies immediately. Settings marked
              <span class="badge bg-warning-subtle text-warning-emphasis border border-warning-subtle">restart</span>
              are changed in concert.env and take effect when concert restarts. Reset removes a value from settings.json.
            </p>
            <p class="small mb-0 text-break">File: <span class="font-monospace" id="settings-file">–</span></p>
          </div></div>
          <div class="card stat-card"><div class="card-body">
            <h2 class="h6 mb-3"><i aria-hidden="true" class="bi bi-lock"></i> Environment only, and listeners</h2>
            <dl class="row small mb-0" id="settings-fixed"></dl>
          </div></div>
        </div>
      </div>
    </div>

    <!-- Email delivery, DNS verification & scheduled event digest -->
    <div class="tab-pane fade" id="tab-email" role="tabpanel" aria-labelledby="tab-email-btn" tabindex="0">
      <div class="alert alert-warning d-none" id="email-readonly-alert" role="alert">
        <i aria-hidden="true" class="bi bi-lock"></i> <code>-read-only-settings</code> (GitOps mode) is enabled: configuration changes and portal credential writes are locked. Provide settings and secrets via flags or <code>CONCERT_*</code> environment variables.
      </div>
      <div class="alert alert-info d-none" id="email-secret-note" role="alert"></div>
      <div class="alert alert-secondary d-none" id="email-paused-alert" role="alert">
        <i aria-hidden="true" class="bi bi-pause-circle"></i> Scheduled email digests are currently <strong>paused</strong>. Runtime events continue queuing until resumed.
      </div>

      <div class="row g-3">
        <!-- Left column: provider, schedule cadence & compliance form -->
        <div class="col-xl-7">
          <form id="email-form" class="d-grid gap-3" novalidate>
            <div class="card stat-card">
              <div class="card-body">
                <div class="d-flex flex-wrap align-items-center justify-content-between gap-2 mb-3">
                  <h2 class="h6 mb-0"><i aria-hidden="true" class="bi bi-send-check"></i> Delivery provider &amp; credentials</h2>
                  <span class="badge text-bg-secondary" id="email-provider-badge">Disabled</span>
                </div>
                <div class="row g-3">
                  <div class="col-md-6">
                    <label for="email-provider" class="form-label">Provider</label>
                    <select class="form-select form-select-sm" id="email-provider">
                      <option value="">Disabled (off)</option>
                      <option value="smtp">SMTP (Username &amp; Password)</option>
                      <option value="resend">Resend (API Key)</option>
                      <option value="sendpanda">SendPanda (sendpanda.email API Key)</option>
                    </select>
                  </div>
                  <div class="col-md-6">
                    <label for="email-dkim-selector" class="form-label">DKIM selector <span class="text-body-secondary small">(optional DNS check)</span></label>
                    <input type="text" class="form-control form-control-sm font-monospace" id="email-dkim-selector" placeholder="e.g. resend, s1, default">
                  </div>
                </div>

                <!-- SMTP provider fields -->
                <div id="email-smtp-fields" class="row g-3 mt-1 d-none">
                  <div class="col-md-5">
                    <label for="email-smtp-host" class="form-label">SMTP host</label>
                    <input type="text" class="form-control form-control-sm font-monospace" id="email-smtp-host" placeholder="smtp.example.com">
                  </div>
                  <div class="col-md-3">
                    <label for="email-smtp-port" class="form-label">Port</label>
                    <input type="number" class="form-control form-control-sm font-monospace" id="email-smtp-port" min="1" max="65535" value="587">
                  </div>
                  <div class="col-md-4">
                    <label for="email-smtp-tls" class="form-label">TLS mode</label>
                    <select class="form-select form-select-sm" id="email-smtp-tls">
                      <option value="starttls">STARTTLS (port 587)</option>
                      <option value="tls">Implicit TLS / SMTPS (port 465)</option>
                      <option value="none">None (local relay only)</option>
                    </select>
                  </div>
                  <div class="col-md-6">
                    <label for="email-smtp-user" class="form-label">SMTP username</label>
                    <input type="text" class="form-control form-control-sm font-monospace" id="email-smtp-user" autocomplete="off" placeholder="alerts@example.com">
                  </div>
                  <div class="col-md-6">
                    <div class="d-flex justify-content-between align-items-center">
                      <label for="email-smtp-pass" class="form-label mb-1">SMTP password</label>
                      <span class="badge text-bg-light border" id="email-badge-smtp-pass">not set</span>
                    </div>
                    <div class="input-group input-group-sm">
                      <input type="password" class="form-control font-monospace" id="email-smtp-pass" autocomplete="new-password" placeholder="Write-only (blank keeps existing)">
                      <button type="button" class="btn btn-outline-danger d-none" id="email-clear-smtp-pass" title="Remove stored SMTP password"><i aria-hidden="true" class="bi bi-trash"></i></button>
                    </div>
                    <div class="form-text">Stored AES-256-GCM encrypted in <code>email-secrets.json</code>, or override via <code>CONCERT_SMTP_PASS</code>.</div>
                  </div>
                </div>

                <!-- Resend provider fields -->
                <div id="email-resend-fields" class="row g-3 mt-1 d-none">
                  <div class="col-md-6">
                    <div class="d-flex justify-content-between align-items-center">
                      <label for="email-resend-key" class="form-label mb-1">Resend API key</label>
                      <span class="badge text-bg-light border" id="email-badge-resend-key">not set</span>
                    </div>
                    <div class="input-group input-group-sm">
                      <input type="password" class="form-control font-monospace" id="email-resend-key" autocomplete="new-password" placeholder="re_... (write-only)">
                      <button type="button" class="btn btn-outline-danger d-none" id="email-clear-resend-key" title="Remove stored Resend API key"><i aria-hidden="true" class="bi bi-trash"></i></button>
                    </div>
                    <div class="form-text">Override via <code>CONCERT_RESEND_API_KEY</code>. Never returned after saving.</div>
                  </div>
                  <div class="col-md-6">
                    <label for="email-resend-url" class="form-label">Resend API base URL <span class="text-body-secondary small">(optional)</span></label>
                    <input type="url" class="form-control form-control-sm font-monospace" id="email-resend-url" placeholder="https://api.resend.com">
                  </div>
                </div>

                <!-- SendPanda provider fields -->
                <div id="email-sendpanda-fields" class="row g-3 mt-1 d-none">
                  <div class="col-md-6">
                    <div class="d-flex justify-content-between align-items-center">
                      <label for="email-sendpanda-key" class="form-label mb-1">SendPanda API key</label>
                      <span class="badge text-bg-light border" id="email-badge-sendpanda-key">not set</span>
                    </div>
                    <div class="input-group input-group-sm">
                      <input type="password" class="form-control font-monospace" id="email-sendpanda-key" autocomplete="new-password" placeholder="sendpanda.email API key (write-only)">
                      <button type="button" class="btn btn-outline-danger d-none" id="email-clear-sendpanda-key" title="Remove stored SendPanda API key"><i aria-hidden="true" class="bi bi-trash"></i></button>
                    </div>
                    <div class="form-text">Override via <code>CONCERT_SENDPANDA_API_KEY</code>. Never returned after saving.</div>
                  </div>
                  <div class="col-md-6">
                    <label for="email-sendpanda-url" class="form-label">SendPanda API base URL <span class="text-body-secondary small">(editable)</span></label>
                    <input type="url" class="form-control form-control-sm font-monospace" id="email-sendpanda-url" placeholder="https://api.sendpanda.email/v1">
                  </div>
                </div>

                <hr class="my-3">
                <div class="row g-3">
                  <div class="col-md-5">
                    <label for="email-from-name" class="form-label">From display name</label>
                    <input type="text" class="form-control form-control-sm" id="email-from-name" placeholder="Concert">
                  </div>
                  <div class="col-md-7">
                    <label for="email-from-addr" class="form-label">From email address</label>
                    <input type="email" class="form-control form-control-sm font-monospace" id="email-from-addr" placeholder="alerts@yourdomain.com">
                  </div>
                  <div class="col-12">
                    <label for="email-to" class="form-label">Administrator recipients</label>
                    <input type="text" class="form-control form-control-sm font-monospace" id="email-to" placeholder="ops@yourdomain.com, security@yourdomain.com">
                    <div class="form-text">Comma-separated addresses. Each recipient receives an individually signed one-click pause link.</div>
                  </div>
                </div>
              </div>
            </div>

            <!-- Cadence schedule & event categories -->
            <div class="card stat-card">
              <div class="card-body">
                <h2 class="h6 mb-3"><i aria-hidden="true" class="bi bi-clock-history"></i> Digest schedule &amp; rate enforcement</h2>
                <div class="d-flex flex-wrap align-items-center gap-2 mb-2">
                  <span class="small fw-semibold">Send</span>
                  <select class="form-select form-select-sm w-auto" id="email-cadence-max-select" aria-label="Maximum emails per window">
                    <option value="1">1</option>
                    <option value="2">2</option>
                    <option value="4">4</option>
                    <option value="6">6</option>
                    <option value="10">10</option>
                    <option value="12">12</option>
                    <option value="24">24</option>
                    <option value="50">50</option>
                    <option value="100">100</option>
                    <option value="333">333</option>
                    <option value="custom">Custom…</option>
                  </select>
                  <input type="number" class="form-control form-control-sm w-auto d-none" id="email-cadence-max-custom" min="1" max="1000" aria-label="Custom email count">
                  <span class="small fw-semibold">email(s) every</span>
                  <select class="form-select form-select-sm w-auto" id="email-cadence-window-select" aria-label="Cadence window value">
                    <option value="1">1</option>
                    <option value="2">2</option>
                    <option value="4">4</option>
                    <option value="6">6</option>
                    <option value="7">7</option>
                    <option value="12">12</option>
                    <option value="14">14</option>
                    <option value="15">15</option>
                    <option value="24">24</option>
                    <option value="28">28</option>
                    <option value="30">30</option>
                    <option value="45">45</option>
                    <option value="60">60</option>
                    <option value="90">90</option>
                    <option value="120">120</option>
                    <option value="custom">Custom…</option>
                  </select>
                  <input type="number" class="form-control form-control-sm w-auto d-none" id="email-cadence-window-custom" min="1" max="43200" aria-label="Custom window value">
                  <select class="form-select form-select-sm w-auto" id="email-cadence-unit" aria-label="Cadence window unit">
                    <option value="minutes">minutes</option>
                    <option value="hours">hours</option>
                    <option value="days">days</option>
                  </select>
                </div>
                <div class="d-flex flex-wrap gap-1 mb-2" id="email-cadence-presets">
                  <button type="button" class="btn btn-sm btn-outline-secondary" data-max="1" data-win="15" data-unit="minutes">1 / 15m</button>
                  <button type="button" class="btn btn-sm btn-outline-secondary" data-max="4" data-win="90" data-unit="minutes">4 / 90m</button>
                  <button type="button" class="btn btn-sm btn-outline-secondary" data-max="1" data-win="1" data-unit="days">1 / day</button>
                  <button type="button" class="btn btn-sm btn-outline-secondary" data-max="1" data-win="7" data-unit="days">1 / week</button>
                  <button type="button" class="btn btn-sm btn-outline-secondary" data-max="333" data-win="28" data-unit="days">333 / 28d</button>
                </div>
                <div class="small text-body-secondary mb-3" id="email-cadence-preview">Paced digest schedule enforced by Concert.</div>

                <h3 class="h6 small text-uppercase text-body-secondary mb-2">Queued event categories</h3>
                <div class="row g-2 small" id="email-categories">
                  <div class="col-md-6">
                    <div class="form-check">
                      <input class="form-check-input" type="checkbox" id="email-cat-silence" data-cat="silence">
                      <label class="form-check-label" for="email-cat-silence"><strong>Silence &amp; circuit breakers</strong><br><span class="text-body-secondary">Leaf application silence/recovery and upstream CB trips</span></label>
                    </div>
                  </div>
                  <div class="col-md-6">
                    <div class="form-check">
                      <input class="form-check-input" type="checkbox" id="email-cat-capacity" data-cat="capacity">
                      <label class="form-check-label" for="email-cat-capacity"><strong>Capacity &amp; leaf failover</strong><br><span class="text-body-secondary">Unreachable leaves and edge capacity drops</span></label>
                    </div>
                  </div>
                  <div class="col-md-6">
                    <div class="form-check">
                      <input class="form-check-input" type="checkbox" id="email-cat-bans" data-cat="bans">
                      <label class="form-check-label" for="email-cat-bans"><strong>Abuse bans &amp; surges</strong><br><span class="text-body-secondary">Permanent bans, CIDR range bans, and auto-ban surges</span></label>
                    </div>
                  </div>
                  <div class="col-md-6">
                    <div class="form-check">
                      <input class="form-check-input" type="checkbox" id="email-cat-fastlane" data-cat="fastlane">
                      <label class="form-check-label" for="email-cat-fastlane"><strong>Fast-lane reconciliation</strong><br><span class="text-body-secondary">Unresolved payment settlements needing review</span></label>
                    </div>
                  </div>
                  <div class="col-md-6">
                    <div class="form-check">
                      <input class="form-check-input" type="checkbox" id="email-cat-queue" data-cat="queue">
                      <label class="form-check-label" for="email-cat-queue"><strong>Waiting room saturation</strong><br><span class="text-body-secondary">Queue full events and 503 breaker trips</span></label>
                    </div>
                  </div>
                  <div class="col-md-6">
                    <div class="form-check">
                      <input class="form-check-input" type="checkbox" id="email-cat-security" data-cat="security">
                      <label class="form-check-label" for="email-cat-security"><strong>Admin &amp; compliance security</strong><br><span class="text-body-secondary">Portal login lockouts, settings edits, and DSAR actions</span></label>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <!-- Compliance & footer branding -->
            <div class="card stat-card">
              <div class="card-body">
                <h2 class="h6 mb-2"><i aria-hidden="true" class="bi bi-file-earmark-check"></i> Compliance headers, links &amp; footer</h2>
                <p class="small text-body-secondary mb-3">Included automatically with RFC 5322/3834/8058 headers (<code>Auto-Submitted</code>, <code>Precedence: bulk</code>, signed <code>List-Unsubscribe</code> one-click pause) in both HTML and plain-text digests.</p>
                <div class="row g-3">
                  <div class="col-md-6">
                    <label for="email-org-name" class="form-label">Organization name</label>
                    <input type="text" class="form-control form-control-sm" id="email-org-name" placeholder="Acme Operations Inc.">
                  </div>
                  <div class="col-md-6">
                    <label for="email-postal-address" class="form-label">Physical postal address <span class="text-body-secondary small">(CAN-SPAM)</span></label>
                    <input type="text" class="form-control form-control-sm" id="email-postal-address" placeholder="100 Main St, Suite 400, Austin, TX 78701">
                  </div>
                  <div class="col-md-6">
                    <label for="email-portal-url" class="form-label">Admin portal URL</label>
                    <input type="url" class="form-control form-control-sm font-monospace" id="email-portal-url" placeholder="https://portal.example.com">
                  </div>
                  <div class="col-md-6">
                    <label for="email-public-base-url" class="form-label">Public base URL <span class="text-body-secondary small">(one-click unsubscribe)</span></label>
                    <input type="url" class="form-control form-control-sm font-monospace" id="email-public-base-url" placeholder="https://app.example.com">
                  </div>
                  <div class="col-md-6">
                    <label for="email-privacy-url" class="form-label">Privacy policy URL</label>
                    <input type="url" class="form-control form-control-sm font-monospace" id="email-privacy-url" placeholder="https://example.com/privacy">
                  </div>
                  <div class="col-md-6">
                    <label for="email-terms-url" class="form-label">Terms / notice URL</label>
                    <input type="url" class="form-control form-control-sm font-monospace" id="email-terms-url" placeholder="https://example.com/terms">
                  </div>
                </div>
              </div>
              <div class="card-footer d-flex flex-wrap align-items-center gap-2">
                <button type="submit" class="btn btn-sm btn-primary" id="email-save"><i aria-hidden="true" class="bi bi-check2-circle"></i> Save email settings</button>
                <button type="button" class="btn btn-sm btn-outline-secondary" id="email-reload"><i aria-hidden="true" class="bi bi-arrow-counterclockwise"></i> Reload</button>
                <span class="small text-body-secondary ms-auto" id="email-save-status"></span>
              </div>
            </div>
          </form>
        </div>

        <!-- Right column: DNS connectivity check, test send & live event queue -->
        <div class="col-xl-5 d-flex flex-column gap-3">
          <div class="card stat-card">
            <div class="card-body">
              <div class="d-flex flex-wrap align-items-center justify-content-between gap-2 mb-3">
                <h2 class="h6 mb-0"><i aria-hidden="true" class="bi bi-diagram-3"></i> DNS connectivity &amp; test delivery</h2>
                <button type="button" class="btn btn-sm btn-outline-primary" id="email-verify-btn"><i aria-hidden="true" class="bi bi-patch-check"></i> Verify DNS &amp; connection</button>
              </div>
              <p class="small text-body-secondary mb-3">Save settings first, then verify sender MX, SPF, DMARC, optional DKIM selector, recipient MX, provider DNS, and live SMTP/API authentication.</p>
              <div id="email-verify-summary" class="alert d-none py-2 small" role="status"></div>
              <div class="table-responsive d-none" id="email-verify-wrap">
                <table class="table table-sm table-portal mb-3">
                  <thead>
                    <tr>
                      <th scope="col">Check</th>
                      <th scope="col">Status</th>
                      <th scope="col">Result</th>
                    </tr>
                  </thead>
                  <tbody id="email-verify-rows"></tbody>
                </table>
              </div>
              <hr class="my-3">
              <label for="email-test-to" class="form-label small fw-semibold">Send test email</label>
              <div class="input-group input-group-sm">
                <input type="email" class="form-control font-monospace" id="email-test-to" placeholder="Blank sends to first configured recipient">
                <button type="button" class="btn btn-success" id="email-test-btn"><i aria-hidden="true" class="bi bi-envelope-arrow-up"></i> Send test</button>
              </div>
              <div class="small text-body-secondary mt-2" id="email-test-result"></div>
            </div>
          </div>

          <div class="card stat-card">
            <div class="card-body">
              <div class="d-flex flex-wrap align-items-center gap-2 mb-3">
                <h2 class="h6 mb-0"><i aria-hidden="true" class="bi bi-inbox"></i> Event queue &amp; schedule budget</h2>
                <div class="ms-auto d-flex gap-1">
                  <button type="button" class="btn btn-sm btn-outline-warning" id="email-pause-btn"><i aria-hidden="true" class="bi bi-pause-fill"></i> Pause</button>
                  <button type="button" class="btn btn-sm btn-outline-primary" id="email-flush-btn"><i aria-hidden="true" class="bi bi-send"></i> Flush now</button>
                  <button type="button" class="btn btn-sm btn-outline-secondary" id="email-refresh-btn" title="Refresh queue status"><i aria-hidden="true" class="bi bi-arrow-clockwise"></i></button>
                </div>
              </div>
              <div class="d-flex justify-content-between small mb-1">
                <span>Rolling cadence budget</span>
                <span class="fw-semibold" id="email-budget-text">–</span>
              </div>
              <div class="progress mb-2" role="progressbar" aria-label="Email cadence budget used" aria-valuemin="0" aria-valuemax="100">
                <div class="progress-bar" id="email-budget-bar"></div>
              </div>
              <dl class="row stat-list small mb-3">
                <dt class="col-6">Next scheduled send</dt><dd class="col-6 text-end" id="email-next-send">–</dd>
                <dt class="col-6">Queued events</dt><dd class="col-6 text-end" id="email-queued-summary">–</dd>
                <dt class="col-6">Delivered / Failed</dt><dd class="col-6 text-end" id="email-totals">–</dd>
                <dt class="col-6">Last delivery</dt><dd class="col-6 text-end text-break" id="email-last-delivery">–</dd>
              </dl>

              <div class="d-none mb-3" id="email-unsubscribed-wrap">
                <h3 class="h6 small text-uppercase text-body-secondary mb-2">Paused / unsubscribed recipients</h3>
                <ul class="list-group list-group-flush small" id="email-unsubscribed-list"></ul>
              </div>

              <h3 class="h6 small text-uppercase text-body-secondary mb-2">Pending digest events</h3>
              <div class="table-responsive">
                <table class="table table-sm table-portal mb-0">
                  <thead>
                    <tr>
                      <th scope="col">Severity</th>
                      <th scope="col">Event</th>
                      <th scope="col" class="text-end">Count</th>
                    </tr>
                  </thead>
                  <tbody id="email-queue-rows"></tbody>
                </table>
              </div>
            </div>
          </div>
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
            Visitors waiting in line from the banned network are removed immediately.
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
        <button type="submit" class="btn btn-danger"><i aria-hidden="true" class="bi bi-slash-circle"></i> <span id="ban-submit-label">Ban</span></button>
      </div>
    </form>
  </div>
</div>
{{end}}
{{template "footer" .}}