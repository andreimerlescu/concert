{{/* Table fragments for the admin portal; see fragments.go. Rows carry
     data-key so portal.js can match them between refreshes. Times are unix
     milliseconds, formatted by the browser (js-time, js-ago, js-since,
     js-left), so a row's HTML changes only when its data does. */}}

{{define "ipcell"}}<div class="ipcell">
<div class="d-flex align-items-center gap-1 flex-wrap">
{{if .Info.Found}}<span class="ip-flag" role="img" aria-label="{{.Info.CountryTitle}}" data-bs-toggle="tooltip" data-bs-title="{{.Info.CountryTitle}}">{{.Info.Flag}}</span>{{end}}
<span class="font-monospace ip-text">{{.Text}}</span>
{{if .Prefix}}{{if .RangeBadge}}<span class="badge text-bg-secondary">range</span>{{end}}{{else}}{{range .Info.Badges}}<button type="button" class="badge rounded-pill ip-badge ip-badge-v{{.Label}}" data-bs-toggle="tooltip" data-bs-custom-class="tip-pre" data-bs-title="{{.Tip}}" data-copy="{{.Copy}}" aria-label="Copy IPv{{.Label}} address {{.Copy}}">{{.Label}}</button>{{end}}{{end}}
</div>
{{if .Info.Found}}<div class="ip-asn small text-body-secondary text-truncate" title="{{.Info.ASN}} {{.Info.Description}}">{{if .Info.Routed}}{{.Info.ASN}} · {{end}}{{.Info.Description}}</div>{{end}}
</div>{{end}}

{{define "ip-facts"}}<div class="ip-facts">{{template "ipcell" .}}{{with .Info}}{{if .Found}}
<dl class="row small mb-0 mt-2">
<dt class="col-4 text-body-secondary fw-normal">Country</dt><dd class="col-8 mb-1">{{.Flag}} {{.Country}} <span class="text-body-secondary">({{.CountryCode}})</span></dd>
<dt class="col-4 text-body-secondary fw-normal">Network</dt><dd class="col-8 mb-1">{{if .Routed}}{{.ASN}} · {{else}}not routed · {{end}}{{.Description}}</dd>
{{if .Range}}<dt class="col-4 text-body-secondary fw-normal">Range</dt><dd class="col-8 mb-1 font-monospace">{{.Range}}</dd>{{end}}
{{if .Range8}}<dt class="col-4 text-body-secondary fw-normal">IPv8 range</dt><dd class="col-8 mb-1 font-monospace"><span data-bs-toggle="tooltip" data-bs-custom-class="tip-pre" data-bs-title="ASN dot form&#10;{{.Range8ASN}}">{{.Range8}}</span></dd>{{end}}
</dl>{{else if ipinfoOn}}<div class="small text-body-secondary mt-1">Not in the IP database.</div>{{end}}{{end}}</div>{{end}}

{{define "status"}}<span class="badge {{statusBadge .}}">{{.}}</span>{{end}}

{{/* ── Visitors ─────────────────────────────────────────────────────── */}}

{{define "visitor-rows"}}{{$abuse := .AbuseOn}}{{range .Rows}}<tr data-key="{{.Client}}" class="{{.RowClass}}" data-first="{{.FirstMS}}" data-last="{{.LastMS}}">
<td class="history-toggle"><button type="button" class="btn btn-sm btn-link text-body p-0" data-action="toggle" aria-expanded="false" aria-label="Show details"><i aria-hidden="true" class="bi bi-chevron-right"></i></button></td>
<td class="cell-ip" data-chip>{{template "ipcell" (ipcell .Client)}}</td>
<td class="text-nowrap">{{if .BannedNow}}{{if .BanPermanent}}<span class="badge text-bg-danger">banned permanently</span>{{else}}<span class="badge text-bg-warning">banned · <span class="js-left" data-ms="{{.BanUntilMS}}"></span> left</span>{{end}}{{else if or .BansTriggered .Blocked}}<span class="badge text-bg-secondary">was banned</span>{{else}}<span class="badge text-bg-light border">ok</span>{{end}}{{with .Rank}} <span class="badge text-bg-primary" data-bs-toggle="tooltip" data-bs-title="Priority rank granted by the application (Concert-Priority)">{{.}}</span>{{end}}</td>
<td>{{num .Requests}}</td>
<td class="{{if .Blocked}}fw-semibold text-danger{{else}}text-body-secondary{{end}}">{{num .Blocked}}</td>
<td class="{{if .Errors}}fw-semibold{{else}}text-body-secondary{{end}}">{{num .Errors}}</td>
<td class="small text-nowrap"><span class="js-ago" data-ms="{{.LastMS}}"></span></td>
<td class="small text-truncate cell-hist-path" title="{{.LastMethod}} {{.LastPath}}">{{template "status" .LastStatus}} <span class="font-monospace">{{.LastMethod}} {{.LastPath}}</span></td>
<td class="text-end text-nowrap"><button type="button" class="btn btn-sm btn-outline-danger" data-action="ban" data-client="{{.Client}}" aria-label="Ban this address" title="Ban this address"{{if or .BannedNow (not $abuse)}} disabled{{end}}><i aria-hidden="true" class="bi bi-slash-circle"></i></button></td>
</tr>
{{end}}{{end}}

{{define "detail-pager"}}{{if gt .Pages 1}}<div class="btn-group btn-group-sm ms-auto" role="group" aria-label="Request pages">
<button type="button" class="btn btn-outline-secondary" data-action="detail-page" data-page="{{.Prev}}"{{if not .HasPrev}} disabled{{end}} aria-label="Newer requests"><i aria-hidden="true" class="bi bi-chevron-left"></i></button>
<span class="btn btn-outline-secondary disabled">{{.From}}–{{.To}} of {{.Total}}</span>
<button type="button" class="btn btn-outline-secondary" data-action="detail-page" data-page="{{.Next}}"{{if not .HasNext}} disabled{{end}} aria-label="Older requests"><i aria-hidden="true" class="bi bi-chevron-right"></i></button>
</div>{{end}}{{end}}

{{define "visitor-detail"}}<div class="py-2 history-detail-body">
<div class="row g-3 mb-3">
<div class="col-lg-6">{{template "ip-facts" (ipcell .Client.Client)}}</div>
<div class="col-lg-6 small text-body-secondary">
<div>First seen <time class="js-time" data-ms="{{.Client.FirstMS}}"></time></div>
<div>Last seen <time class="js-time" data-ms="{{.Client.LastMS}}"></time></div>
<div>{{num .Client.Requests}} recorded · {{num .Client.Blocked}} blocked · {{num .Client.Errors}} errors</div>
{{if .UAs}}<div class="text-break mt-1">Browsers: {{range $i, $u := .UAs}}{{if $i}} · {{end}}{{if $u}}{{$u}}{{else}}(none sent){{end}}{{end}}</div>{{end}}
</div>
</div>
{{if .Bans}}<div class="small fw-semibold mb-2">{{plural (len .Bans) "ban"}} covering this address</div>{{range .Bans}}{{template "ban-window" .}}{{end}}{{end}}
<div class="d-flex align-items-center mb-2 gap-2"><div class="small fw-semibold">Requests, newest first</div>{{template "detail-pager" .Pager}}</div>
<div class="table-responsive"><table class="table table-sm table-portal mb-0">
<thead><tr><th scope="col">Time</th><th scope="col">Request</th><th scope="col">Status</th><th scope="col">Response</th><th scope="col">Notes</th><th scope="col">Browser</th></tr></thead>
<tbody>
{{range .Entries}}<tr class="{{.RowClass}}">
<td class="small text-nowrap"><time class="js-time" data-ms="{{.AtMS}}"></time></td>
<td class="small font-monospace text-truncate cell-hist-path" title="{{.Path}}">{{.Method}} {{.Path}}</td>
<td>{{template "status" .Status}}</td>
<td class="small text-nowrap">{{latency .LatencyMS}}</td>
<td class="text-nowrap">{{if .Triggered}}<span class="badge text-bg-danger">started ban</span>{{else if .Blocked}}<span class="badge text-bg-warning">during ban</span>{{end}}{{with .Rank}} <span class="badge text-bg-primary">{{.}}</span>{{end}}</td>
<td class="small text-truncate cell-ua" title="{{.UserAgent}}">{{if .UserAgent}}{{.UserAgent}}{{else}}—{{end}}</td>
</tr>
{{else}}<tr><td colspan="6" class="text-center text-body-secondary py-3">No requests kept.</td></tr>{{end}}
</tbody></table></div>
</div>{{end}}

{{/* ── Ban windows (Ban log and client details) ─────────────────────── */}}

{{define "ban-state"}}{{if .Active}}<span class="badge text-bg-danger">{{if .Permanent}}permanent{{else}}active{{end}}</span>{{else}}<span class="badge text-bg-light border">{{if eq .EndReason "lifted"}}lifted{{else}}expired{{end}}</span>{{end}}{{end}}

{{define "ban-end"}}{{if .Active}}{{if .Permanent}}Never: permanent until someone unbans it{{else}}<time class="js-time" data-ms="{{.UntilMS}}"></time> (<span class="js-left" data-ms="{{.UntilMS}}"></span> left){{end}}{{else if eq .EndReason "lifted"}}Lifted <time class="js-time" data-ms="{{.EndedMS}}"></time>{{with .LiftedBy}} by {{.}}{{end}}{{else}}Expired <time class="js-time" data-ms="{{.EndedMS}}"></time>{{end}}{{end}}

{{define "count-table"}}<div class="small fw-semibold mb-1">{{.Title}}</div>
<table class="table table-sm table-portal mb-0"><tbody>
{{range .Rows}}<tr><td class="small text-break">{{if $.IPs}}{{template "ipcell" (ipcell .Name)}}{{else}}<span class="font-monospace">{{.Name}}</span>{{end}}</td><td class="small text-end fw-semibold text-nowrap">{{num .Hits}}</td></tr>
{{end}}{{if .Other}}<tr><td class="small text-body-secondary">{{.OtherLabel}}</td><td class="small text-end fw-semibold">{{num .Other}}</td></tr>{{end}}
{{if and (not .Rows) (not .Other)}}<tr><td colspan="2" class="text-center text-body-secondary small">None</td></tr>{{end}}
</tbody></table>{{end}}

{{define "ban-window"}}<div class="history-ban border rounded p-3 mb-3">
<div class="d-flex flex-wrap align-items-start gap-2 mb-2"><i aria-hidden="true" class="bi bi-slash-circle text-danger mt-1"></i>{{template "ipcell" (ipcell .Target)}}{{template "ban-state" .}}</div>
<dl class="row small mb-2">
<dt class="col-sm-3 text-body-secondary fw-normal">Began</dt><dd class="col-sm-9 mb-1">{{if .Began}}<time class="js-time" data-ms="{{.BeganMS}}"></time>{{else}}Before concert last started (restored from bans.json){{end}}</dd>
<dt class="col-sm-3 text-body-secondary fw-normal">{{if .Active}}Ends{{else}}Ended{{end}}</dt><dd class="col-sm-9 mb-1">{{template "ban-end" .}}</dd>
{{with .Trigger}}<dt class="col-sm-3 text-body-secondary fw-normal">Started by</dt><dd class="col-sm-9 mb-1 text-break"><span class="font-monospace">{{.Method}} {{.Path}}</span> → {{.Status}}, from <span class="font-monospace">{{.Client}}</span> at <time class="js-time" data-ms="{{ms .At}}"></time></dd>{{else}}{{if and (not .Source) .Began}}<dt class="col-sm-3 text-body-secondary fw-normal">Started by</dt><dd class="col-sm-9 mb-1">Strikes that added up over several requests</dd>{{end}}{{end}}
{{with .Source}}<dt class="col-sm-3 text-body-secondary fw-normal">Issued</dt><dd class="col-sm-9 mb-1">{{.}}</dd>{{end}}
{{with .Changes}}<dt class="col-sm-3 text-body-secondary fw-normal">Changed</dt><dd class="col-sm-9 mb-1">{{plural . "time"}} while in force</dd>{{end}}
<dt class="col-sm-3 text-body-secondary fw-normal">Requests during ban</dt><dd class="col-sm-9 mb-1">{{if .Requests}}{{num .Requests}} blocked · first <time class="js-time" data-ms="{{.FirstHitMS}}"></time> · last <time class="js-time" data-ms="{{.LastHitMS}}"></time>{{else}}None: nothing from this network arrived while it was banned{{end}}</dd>
</dl>
{{if .Requests}}<div class="row g-3">
<div class="col-md-6">{{template "count-table" (counts "Paths requested while banned" .Paths .OtherPaths "Other paths (not itemised)" false)}}</div>
<div class="col-md-6">{{template "count-table" (counts "Addresses that made them" .Clients .OtherClients "Other addresses (not itemised)" true)}}</div>
</div>{{end}}
</div>{{end}}

{{define "banlog-rows"}}{{range .}}<tr data-key="{{.ID}}" class="{{.RowClass}}" data-first="{{.BeganMS}}">
<td class="history-toggle"><button type="button" class="btn btn-sm btn-link text-body p-0" data-action="toggle" aria-expanded="false" aria-label="Show details"><i aria-hidden="true" class="bi bi-chevron-right"></i></button></td>
<td class="cell-ip" data-chip>{{template "ipcell" (ipcell .Target)}}</td>
<td>{{template "ban-state" .}}</td>
<td class="small text-nowrap">{{if .Began}}<time class="js-time" data-ms="{{.BeganMS}}"></time>{{else}}before restart{{end}}</td>
<td class="small">{{template "ban-end" .}}</td>
<td class="{{if .Requests}}fw-semibold text-danger{{else}}text-body-secondary{{end}}">{{num .Requests}}</td>
<td class="small font-monospace text-truncate cell-hist-path" title="{{.TopPaths}}">{{with .TopPaths}}{{.}}{{else}}—{{end}}</td>
<td class="small text-truncate cell-hist-path{{if .Trigger}} font-monospace{{end}}" title="{{.StartedBy}}">{{with .StartedBy}}{{.}}{{else}}—{{end}}</td>
</tr>
{{end}}{{end}}

{{/* ── Queue ─────────────────────────────────────────────────────────── */}}

{{define "queue-rows"}}{{range .}}<tr data-key="{{.ID}}" data-first="{{.JoinedMS}}">
<td class="fw-semibold">{{.PosLabel}}</td>
<td class="cell-ip" data-chip>{{if .Client}}{{template "ipcell" (ipcell .Client)}}{{else}}—{{end}}</td>
<td>{{if .Ready}}<span class="badge text-bg-success">ready</span>{{else if .Idle}}<span class="badge text-bg-secondary">idle</span>{{else}}<span class="badge text-bg-primary">waiting</span>{{end}}{{if .Promoted}} <span class="badge text-bg-info">moved up</span>{{end}}{{if .HasPass}} <span class="badge text-bg-warning">VIP</span>{{end}}{{with .Rank}} <span class="badge text-bg-primary" data-bs-toggle="tooltip" data-bs-title="Priority rank granted by the application (Concert-Priority)">{{.}}</span>{{end}}</td>
<td class="text-nowrap"><span class="js-since" data-ms="{{.JoinedMS}}"></span></td>
<td class="text-nowrap"><span class="js-ago" data-ms="{{.SeenMS}}"></span></td>
<td class="text-truncate cell-path font-monospace small" title="{{.Path}}">{{if .Path}}{{.Path}}{{else}}—{{end}}</td>
<td class="text-truncate cell-ua small" title="{{.UserAgent}}">{{if .UserAgent}}{{.UserAgent}}{{else}}—{{end}}</td>
<td class="text-end text-nowrap"><div class="btn-group btn-group-sm" role="group">
<button type="button" class="btn btn-outline-success" data-action="promote" data-id="{{.ID}}" title="Move to the front" aria-label="Move to the front"><i aria-hidden="true" class="bi bi-skip-start"></i></button>
<button type="button" class="btn btn-outline-warning" data-action="kick" data-id="{{.ID}}" title="Remove from the line" aria-label="Remove from the line"><i aria-hidden="true" class="bi bi-person-dash"></i></button>
<button type="button" class="btn btn-outline-danger" data-action="ban" data-id="{{.ID}}" title="Remove and ban" aria-label="Remove and ban"><i aria-hidden="true" class="bi bi-slash-circle"></i></button>
</div></td>
</tr>
{{end}}{{end}}

{{/* ── Bans ──────────────────────────────────────────────────────────── */}}

{{define "ban-rows"}}{{range .Rows}}<tr data-key="{{.Client}}" class="{{.RowClass}}">
<td class="cell-ip" data-chip>{{template "ipcell" (ipcell .Client)}}</td>
<td class="text-nowrap">{{if .Permanent}}<span class="badge text-bg-danger">permanent</span>{{else}}<time class="js-time" data-ms="{{.UntilMS}}"></time>{{end}}</td>
<td class="text-nowrap">{{if .Permanent}}<span class="text-body-secondary">—</span>{{else}}<span class="js-left" data-ms="{{.UntilMS}}"></span>{{end}}</td>
<td>{{.Offenses}}</td>
<td class="text-end text-nowrap"><div class="btn-group btn-group-sm" role="group">
<button type="button" class="btn btn-outline-secondary" data-action="edit" data-client="{{.Client}}" data-until-ms="{{.UntilMS}}" data-permanent="{{if .Permanent}}1{{else}}0{{end}}" title="Change ban" aria-label="Change ban"><i aria-hidden="true" class="bi bi-pencil"></i></button>
<button type="button" class="btn btn-outline-success" data-action="unban" data-client="{{.Client}}" title="Unban" aria-label="Unban"><i aria-hidden="true" class="bi bi-unlock"></i></button>
</div></td>
</tr>
{{end}}{{end}}