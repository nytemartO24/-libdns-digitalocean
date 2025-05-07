package digitalocean

import (
	"context"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

// Provider implements the libdns interfaces for DigitalOcean
type Provider struct {
	Client
	// APIToken is the DigitalOcean API token - see https://www.digitalocean.com/docs/apis-clis/api/create-personal-access-token/
	APIToken string `json:"auth_token"`
}

// unFQDN trims any trailing "." from fqdn. DigitalOcean's API does not use FQDNs.
func (p *Provider) unFQDN(fqdn string) string {
	return strings.TrimSuffix(fqdn, ".")
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	rrs, err := p.getDNSEntries(ctx, p.unFQDN(zone))
	if err != nil {
		return nil, err
	}

	var records []libdns.Record
	for _, rr := range rrs {
		switch rr.Type {
		case "A":
			records = append(records, libdns.A{
				Name: rr.Name,
				TTL:  rr.TTL,
				A:    rr.Data,
			})
		case "TXT":
			records = append(records, libdns.TXT{
				Name: rr.Name,
				TTL:  rr.TTL,
				Text: rr.Data,
			})
		// Add cases for other record types as needed
		default:
			// Skip unsupported types or handle as needed
		}
	}

	return records, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var appendedRecords []libdns.Record

	for _, record := range records {
		rr := recordToRR(record)
		newRecord, err := p.addDNSEntry(ctx, p.unFQDN(zone), rr)
		if err != nil {
			return nil, err
		}
		newRecord.TTL = time.Duration(newRecord.TTL) * time.Second
		appendedRecords = append(appendedRecords, recordFromRR(newRecord))
	}

	return appendedRecords, nil
}

// DeleteRecords deletes the records from the zone.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var deletedRecords []libdns.Record

	for _, record := range records {
		rr := recordToRR(record)
		deletedRecord, err := p.removeDNSEntry(ctx, p.unFQDN(zone), rr)
		if err != nil {
			return nil, err
		}
		deletedRecord.TTL = time.Duration(deletedRecord.TTL) * time.Second
		deletedRecords = append(deletedRecords, recordFromRR(deletedRecord))
	}

	return deletedRecords, nil
}

// SetRecords sets the records in the zone, either by updating existing records
// or creating new ones. It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var setRecords []libdns.Record

	for _, record := range records {
		rr := recordToRR(record)
		setRecord, err := p.updateDNSEntry(ctx, p.unFQDN(zone), rr)
		if err != nil {
			return setRecords, err
		}
		setRecord.TTL = time.Duration(setRecord.TTL) * time.Second
		setRecords = append(setRecords, recordFromRR(setRecord))
	}

	return setRecords, nil
}

// Converts a libdns.Record to a simplified RR struct for internal use.
func recordToRR(record libdns.Record) RR {
	switch r := record.(type) {
	case libdns.A:
		return RR{Name: r.Name, TTL: r.TTL, Type: "A", Data: r.A}
	case libdns.TXT:
		return RR{Name: r.Name, TTL: r.TTL, Type: "TXT", Data: r.Text}
	// Add more types here as needed
	default:
		return RR{} // or panic/log
	}
}

// Converts internal RR back to libdns.Record
func recordFromRR(rr RR) libdns.Record {
	switch rr.Type {
	case "A":
		return libdns.A{Name: rr.Name, TTL: rr.TTL, A: rr.Data}
	case "TXT":
		return libdns.TXT{Name: rr.Name, TTL: rr.TTL, Text: rr.Data}
	// Add more types here as needed
	default:
		return nil
	}
}

// RR is an internal struct mimicking libdns.RR just for transitional compatibility
type RR struct {
	Name string
	TTL  time.Duration
	Type string
	Data string
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)

