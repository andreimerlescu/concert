package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/andreimerlescu/concert/internal/fastlane"
	"github.com/andreimerlescu/concert/internal/gateway"
	"github.com/gin-gonic/gin"
)

// Wallet-access configuration is edited in the portal and applied without a
// restart. The two JSON files stay the source of truth (docs/FASTLANE.md), so
// a restart loads exactly what the portal saved. Secrets are never part of
// them: sponsor keys, the policy token and the admission secret come from the
// environment and still take a restart to change.

// laneFiles names the fast-lane and networks files. explicit reports that the
// operator named the fast-lane file, so it must exist; otherwise the defaults
// under the data directory are used when present.
func laneFiles(c *config) (fl, nw string, explicit bool) {
	fl, nw = c.fastlaneFile, c.networksFile
	if fl == "" && c.dataDir != "" {
		fl = filepath.Join(c.dataDir, "fastlane.json")
	}
	if nw == "" && c.dataDir != "" {
		nw = filepath.Join(c.dataDir, "networks.json")
	}
	return fl, nw, c.fastlaneFile != ""
}

// openLane builds the fast lane and its gateway from the two files. It returns
// a nil service when the file says "enabled": false.
func openLane(c *config, flPath, nwPath string) (*fastlane.Service, fastlane.Gateway, error) {
	fc, err := fastlane.Load(flPath)
	if err != nil {
		return nil, nil, err
	}
	if !fc.Enabled {
		return nil, nil, nil
	}
	if c.admitSecretGenerated {
		return nil, nil, errors.New("fast lane requires a stable CONCERT_ADMIT_SECRET")
	}
	cc := *c
	cc.networksFile = nwPath
	gw, err := newGateway(fc, &cc)
	if err != nil {
		return nil, nil, err
	}
	svc, err := fastlane.New(fc, c.dataDir, c.admitSecret, gw, os.Getenv("CONCERT_POLICY_TOKEN"))
	if err != nil {
		closeGateway(gw)
		return nil, nil, err
	}
	return svc, gw, nil
}

// setLane installs a fast lane and its gateway, wiring in the entry window's
// length from the live settings so a change applies without a reload.
func (a *app) setLane(svc *fastlane.Service, gw fastlane.Gateway) {
	if svc != nil {
		svc.SetEntryTTL(func() time.Duration { return a.current().cfg.fastlaneEntryTTL })
	}
	a.lane.Store(svc)
	a.laneGW = gw
}

// closeLane stops the fast lane, then its gateway, which first lets
// settlements in flight journal their results.
func (a *app) closeLane() {
	a.laneMu.Lock()
	defer a.laneMu.Unlock()
	a.closeLaneLocked()
}

func (a *app) closeLaneLocked() {
	if svc := a.lane.Swap(nil); svc != nil {
		svc.Close()
	}
	if a.laneGW != nil {
		closeGateway(a.laneGW)
		a.laneGW = nil
	}
}

// laneConfigView is what the portal editor shows.
type laneConfigView struct {
	Fastlane string `json:"fastlane"`
	Networks string `json:"networks"`
	Path     string `json:"fastlane_path"`
	NetPath  string `json:"networks_path"`
	Saved    bool   `json:"saved"`
	Running  bool   `json:"running"`
	Writable bool   `json:"writable"`
}

func (a *app) laneConfigView() laneConfigView {
	cfg := a.current().cfg
	fl, nw, _ := laneFiles(&cfg)
	v := laneConfigView{Path: fl, NetPath: nw, Running: a.lane.Load() != nil, Writable: cfg.dataDir != "" || cfg.fastlaneFile != ""}
	read := func(path, example string) string {
		if b, err := os.ReadFile(path); err == nil && path != "" {
			v.Saved = true
			return string(b)
		}
		b, _ := examples.ReadFile("examples/" + example)
		return string(b)
	}
	v.Fastlane = read(fl, "fastlane.json")
	v.Networks = read(nw, "networks.json")
	return v
}

// checkLaneConfig validates both documents exactly as startup would, short of
// contacting a chain or opening a journal.
func (a *app) checkLaneConfig(flJSON, nwJSON []byte) (fastlane.Config, error) {
	fc, err := fastlane.Parse(bytes.NewReader(flJSON))
	if err != nil {
		return fc, fmt.Errorf("fast lane settings: %w", err)
	}
	nets, err := gateway.ParseNetworks(bytes.NewReader(nwJSON))
	if err != nil {
		return fc, fmt.Errorf("network settings: %w", err)
	}
	if fc.Enabled {
		if a.current().cfg.admitSecretGenerated {
			return fc, errors.New("wallet access needs a stable CONCERT_ADMIT_SECRET in the environment; set it and restart once")
		}
		if err := gateway.Check(fc, nets, os.Getenv); err != nil {
			return fc, fmt.Errorf("network settings: %w", err)
		}
	}
	return fc, nil
}

func writeAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".concert-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err = tmp.Chmod(0o640); err != nil {
		tmp.Close()
		return err
	}
	if _, err = tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func payTos(c fastlane.Config) []string {
	var out []string
	for _, o := range c.Offers {
		out = append(out, o.Requirements.Network+"="+o.Requirements.PayTo)
	}
	sort.Strings(out)
	return out
}

// applyLaneConfig saves both documents and switches the running fast lane to
// them. Wallet requests get a brief 503 while the old service and gateway
// release their journals; if the new configuration will not start, the old
// files and service are restored and the error is returned.
func (a *app) applyLaneConfig(flJSON, nwJSON []byte) error {
	a.laneMu.Lock()
	defer a.laneMu.Unlock()
	cfg := a.current().cfg
	fl, nw, _ := laneFiles(&cfg)
	if fl == "" || nw == "" {
		return errors.New("set CONCERT_DATA_DIR (or the fast-lane and networks file paths) so settings can be saved")
	}
	newCfg, err := a.checkLaneConfig(flJSON, nwJSON)
	if err != nil {
		return err
	}
	oldFL, _ := os.ReadFile(fl)
	oldNW, _ := os.ReadFile(nw)
	var oldCfg fastlane.Config
	if len(oldFL) > 0 {
		oldCfg, _ = fastlane.Parse(bytes.NewReader(oldFL))
	}
	restore := func() {
		for path, b := range map[string][]byte{fl: oldFL, nw: oldNW} {
			if b != nil {
				_ = writeAtomic(path, b)
			} else {
				_ = os.Remove(path)
			}
		}
	}
	if err = writeAtomic(fl, flJSON); err != nil {
		return err
	}
	if err = writeAtomic(nw, nwJSON); err != nil {
		restore()
		return err
	}
	a.laneReloading.Store(true)
	defer a.laneReloading.Store(false)
	a.closeLaneLocked()
	svc, gw, err := openLane(&cfg, fl, nw)
	if err != nil {
		restore()
		if oldSvc, oldGW, e2 := openLane(&cfg, fl, nw); e2 == nil {
			a.setLane(oldSvc, oldGW)
		} else {
			log.Printf("fast lane: reload failed (%v) and the previous configuration would not restart either (%v); wallet access is off", err, e2)
		}
		return fmt.Errorf("the new settings would not start: %w", err)
	}
	a.setLane(svc, gw)
	log.Printf("fast lane: settings applied from the portal: enabled=%t, %d offer(s), %d collection(s)", newCfg.Enabled, len(newCfg.Offers), len(newCfg.Collections))
	if before, after := strings.Join(payTos(oldCfg), " "), strings.Join(payTos(newCfg), " "); before != after {
		log.Printf("fast lane: RECEIVING ADDRESSES CHANGED from the portal: was [%s] now [%s]", before, after)
	}
	return nil
}

func (p *portal) apiFastlaneConfig(c *gin.Context) {
	c.JSON(http.StatusOK, p.a.laneConfigView())
}

func (p *portal) apiFastlaneConfigSave(c *gin.Context) {
	var in struct {
		Fastlane string `json:"fastlane"`
		Networks string `json:"networks"`
		DryRun   bool   `json:"dry_run"`
	}
	d := json.NewDecoder(io.LimitReader(c.Request.Body, 2<<20))
	if err := d.Decode(&in); err != nil || len(in.Fastlane) > 1<<20 || len(in.Networks) > 1<<20 {
		jsonError(c, http.StatusBadRequest, "send the two settings documents as JSON strings, each under 1 MB")
		return
	}
	if in.DryRun {
		if _, err := p.a.checkLaneConfig([]byte(in.Fastlane), []byte(in.Networks)); err != nil {
			jsonError(c, http.StatusBadRequest, err.Error())
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "applied": false})
		return
	}
	if err := p.a.applyLaneConfig([]byte(in.Fastlane), []byte(in.Networks)); err != nil {
		jsonError(c, http.StatusBadRequest, err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "applied": true, "running": p.a.lane.Load() != nil})
}

func (p *portal) apiFastlaneDelivered(c *gin.Context) {
	var in struct {
		Fingerprint string `json:"fingerprint"`
	}
	lane := p.a.lane.Load()
	if lane == nil {
		jsonError(c, http.StatusConflict, "wallet access is off")
		return
	}
	if err := json.NewDecoder(io.LimitReader(c.Request.Body, 4<<10)).Decode(&in); err != nil || in.Fingerprint == "" {
		jsonError(c, http.StatusBadRequest, "send the sale's fingerprint")
		return
	}
	if err := lane.MarkDelivered(in.Fingerprint); err != nil {
		jsonError(c, http.StatusBadRequest, err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
