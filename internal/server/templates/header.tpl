{{define "header"}}<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow">
  {{if .CSRF}}<meta name="csrf-token" content="{{.CSRF}}">{{end}}
  <title>{{.Title}} · Concert</title>
  <script src="/assets/{{.ThemeJS}}"></script>
  <link rel="stylesheet" href="/assets/{{.BootstrapCSS}}">
  <link rel="stylesheet" href="/assets/{{.IconsCSS}}">
  <link rel="stylesheet" href="/assets/{{.PortalLight}}">
  <link rel="stylesheet" href="/assets/{{.PortalThemes}}">
</head>
<body>
<nav class="navbar border-bottom bg-body sticky-top">
  <div class="container-fluid">
    <a class="navbar-brand fw-semibold" href="/"><i aria-hidden="true" class="bi bi-soundwave"></i> concert<span class="brand-period">.</span></a>
    <span class="navbar-text small text-body-secondary d-none d-md-inline">
      <i aria-hidden="true" class="bi bi-arrow-right-short"></i> <span class="font-monospace">{{.Upstream}}</span>
    </span>
    <div class="ms-auto d-flex align-items-center gap-2">
      <div class="dropdown">
        <button type="button" class="btn btn-outline-secondary btn-sm dropdown-toggle" id="theme-menu" data-bs-toggle="dropdown" aria-expanded="false" aria-haspopup="menu" aria-label="Theme">
          <i aria-hidden="true" class="bi bi-palette"></i> <span class="d-none d-sm-inline" id="theme-name">Theme</span>
        </button>
        <ul class="dropdown-menu dropdown-menu-end theme-menu" id="theme-options" role="menu" aria-labelledby="theme-menu"></ul>
      </div>
      {{if .Authed}}
      <form method="post" action="/logout" class="m-0">
        <input type="hidden" name="csrf" value="{{.CSRF}}">
        <button type="submit" class="btn btn-outline-danger btn-sm"><i aria-hidden="true" class="bi bi-box-arrow-right"></i> Sign out</button>
      </form>
      {{end}}
    </div>
  </div>
</nav>
<main class="container-fluid py-4">
{{end}}