package main

import (
	"net/http"
	"testing"
)

func TestCheckPathList(t *testing.T) {
	for _, ok := range []string{"", "/a", " /a , /b/* ", "/a,,/b,", "/x,/x/*"} {
		if err := checkPathList(ok); err != nil {
			t.Errorf("%q: unexpected error %v", ok, err)
		}
	}
	for _, bad := range []string{"a", "/a,b", "/a,/a", " /a , /a ", "/a b"} {
		if err := checkPathList(bad); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}

func TestSettings_PathListsMarkedForPortal(t *testing.T) {
	a, err := newApp(testConfig("http://127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	want := map[string]bool{"bypass": true, "assets": true, "asset_public": true, "ban_paths": true, "stream_paths": true}
	views, _ := a.settingsViews()
	for _, v := range views {
		if got := v.List == listPaths; got != want[v.Key] {
			t.Errorf("%s: list=%q", v.Key, v.List)
		}
	}
}

func TestSettings_PathListEntriesValidated(t *testing.T) {
	a, p, _ := newTestPortal(t, portalTestConfig("http://127.0.0.1:1"), nil)
	ck, csrf := portalLogin(t, p)

	for name, body := range map[string]string{
		"no leading slash": `{"ban_paths":"/.env,.git/*"}`,
		"duplicate":        `{"ban_paths":"/.env,/.env"}`,
	} {
		if rec := portalDo(p, http.MethodPost, "/api/settings", body, ck, csrf, false); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d %s, want 400", name, rec.Code, rec.Body.String())
		}
	}
	if len(a.current().banRules) != 0 {
		t.Error("a rejected list must not apply")
	}

	rec := portalDo(p, http.MethodPost, "/api/settings", `{"ban_paths":"/.env, /.git/*"}`, ck, csrf, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid list: %d %s", rec.Code, rec.Body.String())
	}
	if len(a.current().banRules) != 2 {
		t.Errorf("ban rules: %+v", a.current().banRules)
	}
	if s := findSetting(t, decodeJSON(t, rec), "ban_paths"); s["list"] != listPaths {
		t.Errorf("ban_paths view should carry the list kind: %v", s)
	}
}
