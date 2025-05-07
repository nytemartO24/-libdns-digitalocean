package digitalocean

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/digitalocean/godo"
	"github.com/libdns/libdns"
)

type Client struct {
	client *godo.Client
	mutex  sync.Mutex
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
			var record libdns.Record
			switch entry.Type {
			case "A", "AAAA":
				record = &libdns.Address{
					Address: entry.Data,
					Type:    entry.Type,
					Name:    entry.Name,
					TTL:     time.Duration(entry.TTL) * time.Second,
					ID:      strconv.Itoa(entry.ID),
				}
			case "CNAME":
				record = &libdns.CNAME{
					CNAME: entry.Data,
					Name:  entry.Name,
					TTL:   time.Duration(entry.TTL) * time.Second,
					ID:    strconv.Itoa(entry.ID),
				}
			case "TXT":
				record = &libdns.TXT{
					Text: entry.Data,
					Name: entry.Name,
					TTL:  time.Duration(entry.TTL) * time.Second,
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

	typeName := recordType(record)
	name := recordName(record)
	data := recordValue(record)
	ttl := int(recordTTL(record).Seconds())

	req := &godo.DomainRecordEditRequest{
		Type: typeName,
		Name: name,
		Data: data,
		TTL:  ttl,
	}

	rec, _, err := p.client.Domains.CreateRecord(ctx, zone, req)
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

	id, err := strconv.Atoi(record.ID())
	if err != nil {
		return record, err
	}

	_, err = p.client.Domains.DeleteRecord(ctx, zone, id)
	return record, err
}

func (p *Provider) updateDNSEntry(ctx context.Context, zone string, record libdns.Record) (libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.getClient()

	id, err := strconv.Atoi(record.ID())
	if err != nil {
		return record, err
	}

	req := &godo.DomainRecordEditRequest{
		Type: recordType(record),
		Name: recordName(record),
		Data: recordValue(record),
		TTL:  int(recordTTL(record).Seconds()),
	}

	_, _, err = p.client.Domains.EditRecord(ctx, zone, id, req)
	return record, err
}

// --- helper funcs for record interface access ---

func recordType(r libdns.Record) string {
	switch v := r.(type) {
	case *libdns.Address:
		return v.Type
	case *libdns.CNAME:
		return "CNAME"
	case *libdns.TXT:
		return "TXT"
	default:
		return ""
	}
}

func recordName(r libdns.Record) string {
	switch v := r.(type) {
	case *libdns.Address:
		return v.Name
	case *libdns.CNAME:
		return v.Name
	case *libdns.TXT:
		return v.Name
	default:
		return ""
	}
}

func recordValue(r libdns.Record) string {
	switch v := r.(type) {
	case *libdns.Address:
		return v.Address
	case *libdns.CNAME:
		return v.CNAME
	case *libdns.TXT:
		return v.Text
	default:
		return ""
	}
}

func recordTTL(r libdns.Record) time.Duration {
	switch v := r.(type) {
	case *libdns.Address:
		return v.TTL
	case *libdns.CNAME:
		return v.TTL
	case *libdns.TXT:
		return v.TTL
	default:
		return 0
	}
}

func setRecordID(r libdns.Record, id string) {
	switch v := r.(type) {
	case *libdns.Address:
		v.ID = id
	case *libdns.CNAME:
		v.ID = id
	case *libdns.TXT:
		v.ID = id
	}
}
