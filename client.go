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
			case "A":
				record = libdns.A{Address: entry.Data}
			case "AAAA":
				record = libdns.AAAA{Address: entry.Data}
			case "CNAME":
				record = libdns.CNAME{CNAME: entry.Data}
			case "TXT":
				record = libdns.TXT{Text: entry.Data}
			default:
				continue // skip unsupported types
			}

			record.SetName(entry.Name)
			record.SetTTL(time.Duration(entry.TTL) * time.Second)
			record.SetID(strconv.Itoa(entry.ID))

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
	record.SetID(strconv.Itoa(rec.ID))
	return record, nil
}

func (p *Provider) removeDNSEntry(ctx context.Context, zone string, record libdns.Record) (libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.getClient()

	id, err := strconv.Atoi(record.IDString())
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

	id, err := strconv.Atoi(record.IDString())
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

// Converts a libdns.Record into a DigitalOcean DomainRecordEditRequest.
func toDomainRecordEditRequest(record libdns.Record) (godo.DomainRecordEditRequest, error) {
	ttl := int(record.TTL().Seconds())
	switch r := record.(type) {
	case libdns.A:
		return godo.DomainRecordEditRequest{
			Type: "A", Name: r.Name(), Data: r.Address, TTL: ttl,
		}, nil
	case libdns.AAAA:
		return godo.DomainRecordEditRequest{
			Type: "AAAA", Name: r.Name(), Data: r.Address, TTL: ttl,
		}, nil
	case libdns.CNAME:
		return godo.DomainRecordEditRequest{
			Type: "CNAME", Name: r.Name(), Data: r.CNAME, TTL: ttl,
		}, nil
	case libdns.TXT:
		return godo.DomainRecordEditRequest{
			Type: "TXT", Name: r.Name(), Data: r.Text, TTL: ttl,
		}, nil
	default:
		return godo.DomainRecordEditRequest{}, &libdns.UnsupportedRecordError{Record: record}
	}
}
