package netlify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"io"
	"strings"
	"net/url"

	"github.com/libdns/libdns"
)

func (p *Provider) createRecord(ctx context.Context, zoneInfo netlifyZone, record libdns.Record) (netlifyDNSRecord, error) {
	jsonBytes, err := json.Marshal(netlifyRecord(record))
	if err != nil {
		return netlifyDNSRecord{}, err
	}
	reqURL := fmt.Sprintf("%s/dns_zones/%s/dns_records", baseURL, zoneInfo.ID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(jsonBytes))
	if err != nil {
		return netlifyDNSRecord{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	var res []byte
	res, err = p.doAPIRequest(req)
	if err != nil {
		p.Logger.Error(err.Error())
		return netlifyDNSRecord{}, err
	}
	var result netlifyDNSRecord
	err = json.Unmarshal(res,&result)
	if err != nil {
		p.Logger.Error(err.Error())
		return netlifyDNSRecord{}, err
	}

	return result, nil
}

// updateRecord updates a DNS record. oldRec must have both an ID and zone ID.
// Only the non-empty fields in newRec will be changed.
func (p *Provider) updateRecord(ctx context.Context, oldRec netlifyDNSRecord, newRec netlifyDNSRecord) (netlifyDNSRecord, error) {
	reqURL := fmt.Sprintf("%s/dns_zones/%s/dns_records/%s", baseURL, oldRec.DNSZoneID, oldRec.ID)
	jsonBytes, err := json.Marshal(newRec)
	if err != nil {
		return netlifyDNSRecord{}, err
	}

	// PATCH changes only the populated fields; PUT resets Type, Name, Content, and TTL even if empty
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, reqURL, bytes.NewReader(jsonBytes))
	if err != nil {
		p.Logger.Error(err.Error())
		return netlifyDNSRecord{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	var res []byte
	res, err = p.doAPIRequest(req)
	if err != nil {
		p.Logger.Error(err.Error())
		return netlifyDNSRecord{}, err
	}
	var result netlifyDNSRecord
	err = json.Unmarshal(res, &result)
	if err != nil {
		p.Logger.Error(err.Error())
		return netlifyDNSRecord{}, err
	}

	return result, err
}

func (p *Provider) getDNSRecords(ctx context.Context, zoneInfo netlifyZone, rec libdns.Record, matchContent bool) ([]netlifyDNSRecord, error) {
	qs := make(url.Values)
	qs.Set("type", rec.Type)
	qs.Set("name", libdns.AbsoluteName(rec.Name, zoneInfo.Name))
	if matchContent {
		qs.Set("content", rec.Value)
	}

	reqURL := fmt.Sprintf("%s/zones/%s/dns_records?%s", baseURL, zoneInfo.ID, qs.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		p.Logger.Error(err.Error())
		return nil, err
	}

	var res []byte
	res, err = p.doAPIRequest(req)
	if err != nil {
		p.Logger.Error(err.Error())
		return nil, err
	}
	var results []netlifyDNSRecord
	err = json.Unmarshal(res,&results)
	if err != nil {
		p.Logger.Error(err.Error())
		return nil, err
	}
	return results, err
}

func (p *Provider) getZoneInfo(ctx context.Context, zoneName string) (netlifyZone, error) {
	p.zonesMu.Lock()
	defer p.zonesMu.Unlock()

	// if we already got the zone info, reuse it
	if p.zones == nil {
		p.zones = make(map[string]netlifyZone)
	}
	if zone, ok := p.zones[zoneName]; ok {
		return zone, nil
	}
	zoneName = strings.TrimRight(zoneName,".")
	qs := make(url.Values)
	qs.Set("name", zoneName)
	reqURL := fmt.Sprintf("%s/dns_zones?%s", baseURL, qs.Encode())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		p.Logger.Error(err.Error())
		return netlifyZone{}, err
	}

	var resp []byte
	resp, err = p.doAPIRequest(req)
	if err != nil {
		p.Logger.Error(err.Error())
		return netlifyZone{}, err
	}
	var zones []netlifyZone
	err = json.Unmarshal(resp, &zones)
	if err != nil {
		p.Logger.Error(err.Error())
		return netlifyZone{}, err
	}
	if len(zones) != 1 {
		return netlifyZone{}, fmt.Errorf("expected 1 zone, got %d for %s", len(zones), zoneName)
	}

	// cache this zone for possible reuse
	p.zones[zoneName] = zones[0]
	return zones[0], nil
}

// doAPIRequest authenticates the request req and does the round trip. It returns
// the decoded response from Cloudflare if successful; otherwise it returns an
// error including error information from the API if applicable. If result is a
// non-nil pointer, the result field from the API response will be decoded into
// it for convenience.
func (p *Provider) doAPIRequest(req *http.Request) ([]byte, error) {
	req.Header.Set("Authorization", "Bearer "+p.PersonnalAccessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		p.Logger.Error("Error in request")
		return nil, err
	}
	defer resp.Body.Close()

	bytes, err := io.ReadAll(resp.Body)

	if err != nil {
		p.Logger.Error(err.Error())
		return nil, err
	}

	if err != nil {
		p.Logger.Error(err.Error())
		return nil, err
	}

	if resp.StatusCode >= 400 {
		p.Logger.Error("Error in HTTP")
		return nil, fmt.Errorf("got error status: HTTP %d", resp.StatusCode)
	}
	return bytes, nil
}

const baseURL = "https://api.netlify.com/api/v1"
