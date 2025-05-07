package digitalocean

import (
	"context"
	"strings"

	"github.com/libdns/libdns"
)

// unFQDN removes the trailing dot from a zone name.
func (p *Provider) unFQDN(fqdn string) string {
	return strings.TrimSuffix(fqdn, ".")
}

func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	return p.getDNSEntries(ctx, p.unFQDN(zone))
}

func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var appended []libdns.Record

	for _, r := range records {
		created, err := p.addDNSEntry(ctx, p.unFQDN(zone), r)
		if err != nil {
			return nil, err
		}
		appended = append(appended, created)
	}

	return appended, nil
}

func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var deleted []libdns.Record

	for _, r := range records {
		del, err := p.removeDNSEntry(ctx, p.unFQDN(zone), r)
		if err != nil {
			return nil, err
		}
		deleted = append(deleted, del)
	}

	return deleted, nil
}

func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var updated []libdns.Record

	for _, r := range records {
		set, err := p.updateDNSEntry(ctx, p.unFQDN(zone), r)
		if err != nil {
			return nil, err
		}
		updated = append(updated, set)
	}

	return updated, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
)
