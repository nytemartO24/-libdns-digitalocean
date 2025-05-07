package digitalocean

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/digitalocean/godo"
	"github.com/libdns/libdns"
	"github.com/libdns/libdns/dnsutil"
)

type Provider struct {
	APIToken string
	client   *godo.Client
	mutex    sync.Mutex
}

func (p *Provider) getClient() error {
	if p.client == nil {
		p.client = godo.NewFromToken(p.APIToken)
	}
	return nil
}

func (p *Provider) getDNSEntries(ctx context.Context, zone string) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.getClient()

	opt := &godo.ListOptions{}
	var records []libdns.Record

	for {
		domainRecords, resp, err := p.client.Domains.Records(ctx, zone, opt)
		if err != nil {
			return records, err
		}

		for _, entry := range domainRecords {
			record := libdns.Record(nil)
			switch entry.Type {
			case "A", "AAAA":
				record = &libdns.Address{
					Type:  entry.Type,
					Name:  dnsutil.TrimZone(entry.Name, zone),
					TTL:   time.Duration(entry.TTL) * time.Second,
					Value: entry.Data,
					ID:    strconv.Itoa(entry.ID),
				}
			case "CNAME":
				record = &libdns.CNAME{
					Name:  dnsutil.TrimZone(entry.Name, zone),
					TTL:   time.Duration(entry.TTL) * time.Second,
					Target: entry.Data,
					ID:    strconv.Itoa(entry.ID),
				}
			case "TXT":
				record = &libdns.TXT{
					Name: dnsutil.TrimZone(entry.Name, zone),
					TTL:  time.Duration(entry.TTL) * time.Second,
					Text: entry.Data,
					ID:   strconv.Itoa(entry.ID),
				}
			default:
				continue
			}
			records = append(records, record)
		}

		if resp.Links == nil || resp.Links.IsLastPage() {
			break
		}
		page, err := resp.Links.CurrentPage()
		if err != nil {
			return records, err
		}
		opt.Page = page + 1
	}

	return records, nil
}

func (p *Provider) addDNSEntry(ctx context.Context, zone string, record libdns.Record) (libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.getClient()

	entry, err := toDomainRecordEditRequest(record)
	if err != nil {
		return record, err
	}

	rec, _, err := p.client.Domains.CreateRecord(ctx, zone, &entry)
	if err != nil {
		return record, err
	}

	setRecordID(record, strconv.Itoa(rec.ID))
	return record, nil
}

func (p *Provider) removeDNSEntry(ctx context.Context, zone string, record libdns.Record) (libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.getClient()

	id, err := strconv.Atoi(getRecordID(record))
	if err != nil {
		return record, err
	}

	_, err = p.client.Domains.DeleteRecord(ctx, zone, id)
	if err != nil {
		return record, err
	}

	return record, nil
}

func (p *Provider) updateDNSEntry(ctx context.Context, zone string, record libdns.Record) (libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.getClient()

	id, err := strconv.Atoi(getRecordID(record))
	if err != nil {
		return record, err
	}

	entry, err := toDomainRecordEditRequest(record)
	if err != nil {
		return record, err
	}

	_, _, err = p.client.Domains.EditRecord(ctx, zone, id, &entry)
	if err != nil {
		return record, err
	}

	return record, nil
}

func toDomainRecordEditRequest(record libdns.Record) (godo.DomainRecordEditRequest, error) {
	switch r := record.(type) {
	case *libdns.Address:
		return godo.DomainRecordEditRequest{
			Type: r.Type, Name: r.Name, Data: r.Value, TTL: int(r.TTL.Seconds()),
		}, nil
	case *libdns.CNAME:
		return godo.DomainRecordEditRequest{
			Type: "CNAME", Name: r.Name, Data: r.Target, TTL: int(r.TTL.Seconds()),
		}, nil
	case *libdns.TXT:
		return godo.DomainRecordEditRequest{
			Type: "TXT", Name: r.Name, Data: r.Text, TTL: int(r.TTL.Seconds()),
		}, nil
	default:
		return godo.DomainRecordEditRequest{}, &libdns.UnsupportedRecordError{Record: record}
	}
}

func setRecordID(record libdns.Record, id string) {
	switch r := record.(type) {
	case *libdns.Address:
		r.ID = id
	case *libdns.CNAME:
		r.ID = id
	case *libdns.TXT:
		r.ID = id
	}
}

func getRecordID(record libdns.Record) string {
	switch r := record.(type) {
	case *libdns.Address:
		return r.ID
	case *libdns.CNAME:
		return r.ID
	case *libdns.TXT:
		return r.ID
	default:
		return ""
	}
}
