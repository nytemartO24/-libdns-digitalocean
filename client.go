package digitalocean

import (
	"context"
	"log"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/digitalocean/godo"
	"github.com/libdns/libdns"
)

type Provider struct {
	APIToken string `json:"auth_token"`
	client   *godo.Client
	mutex    sync.Mutex
}

// Custom record wrappers with DigitalOcean metadata
type addressRecord struct {
	libdns.Address
	RecordID string
}

type cnameRecord struct {
	libdns.CNAME
	RecordID string
}

type txtRecord struct {
	libdns.TXT
	RecordID string
}

func (p *Provider) getClient() {
	if p.client == nil {
		p.client = godo.NewFromToken(p.APIToken)
	}
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
			ttl := time.Duration(entry.TTL) * time.Second

			switch entry.Type {
			case "A", "AAAA":
				ip, err := netip.ParseAddr(entry.Data)
				if err != nil {
					log.Panicf("Invalid IP address in DO record: %s", entry.Data)
				}
				record = &addressRecord{
					Address: libdns.Address{
						Name: entry.Name,
						TTL:  ttl,
						IP:   ip,
					},
					RecordID: strconv.Itoa(entry.ID),
				}
			case "CNAME":
				record = &cnameRecord{
					CNAME: libdns.CNAME{
						Name:   entry.Name,
						TTL:    ttl,
						Target: entry.Data,
					},
					RecordID: strconv.Itoa(entry.ID),
				}
			case "TXT":
				record = &txtRecord{
					TXT: libdns.TXT{
						Name: entry.Name,
						TTL:  ttl,
						Text: entry.Data,
					},
					RecordID: strconv.Itoa(entry.ID),
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

	req := godo.DomainRecordEditRequest{
		Type: recordType(record),
		Name: recordName(record),
		Data: recordValue(record),
		TTL:  int(recordTTL(record).Seconds()),
	}

	rec, _, err := p.client.Domains.CreateRecord(ctx, zone, &req)
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

	idStr := getRecordID(record)
	if idStr == "" {
		return record, fmt.Errorf("cannot delete record: missing ID for %s (%s)", recordName(record), recordValue(record))
	}

	id, err := strconv.Atoi(idStr)
	if err != nil {
		return record, fmt.Errorf("invalid record ID %q: %w", idStr, err)
	}

	_, err = p.client.Domains.DeleteRecord(ctx, zone, id)
	return record, err
}

func (p *Provider) updateDNSEntry(ctx context.Context, zone string, record libdns.Record) (libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.getClient()

	idStr := getRecordID(record)
	if idStr == "" {
		return record, fmt.Errorf("cannot update record: missing ID for %s (%s)", recordName(record), recordValue(record))
	}

	id, err := strconv.Atoi(idStr)
	if err != nil {
		return record, fmt.Errorf("invalid record ID %q: %w", idStr, err)
	}

	req := godo.DomainRecordEditRequest{
		Type: recordType(record),
		Name: recordName(record),
		Data: recordValue(record),
		TTL:  int(recordTTL(record).Seconds()),
	}

	_, _, err = p.client.Domains.EditRecord(ctx, zone, id, req)
	return record, err
}

// --- helpers ---

func recordType(r libdns.Record) string {
	switch v := r.(type) {
	case *addressRecord:
		if v.IP.Is4() {
			return "A"
		}
		return "AAAA"
	case *cnameRecord:
		return "CNAME"
	case *txtRecord:
		return "TXT"
	case libdns.RR:
		return v.Type
	default:
		log.Panicf("unsupported record type: %T", r)
		return ""
	}
}

func recordName(r libdns.Record) string {
	switch v := r.(type) {
	case *addressRecord, *cnameRecord, *txtRecord:
		return v.(interface{ GetName() string }).GetName()
	case libdns.RR:
		return v.Name
	default:
		log.Panicf("unsupported record name type: %T", r)
		return ""
	}
}

func recordValue(r libdns.Record) string {
	switch v := r.(type) {
	case *addressRecord:
		return v.IP.String()
	case *cnameRecord:
		return v.Target
	case *txtRecord:
		return v.Text
	case libdns.RR:
		return v.Data
	default:
		log.Panicf("unsupported record value type: %T", r)
		return ""
	}
}

func recordTTL(r libdns.Record) time.Duration {
	switch v := r.(type) {
	case *addressRecord, *cnameRecord, *txtRecord:
		return v.(interface{ GetTTL() time.Duration }).GetTTL()
	case libdns.RR:
		return v.TTL
	default:
		log.Panicf("unsupported record ttl type: %T", r)
		return 0
	}
}

func getRecordID(r libdns.Record) string {
	switch v := r.(type) {
	case *addressRecord:
		return v.RecordID
	case *cnameRecord:
		return v.RecordID
	case *txtRecord:
		return v.RecordID
	case libdns.RR:
		// This record has no ID (likely an ACME challenge). Let the caller decide how to proceed.
		return ""
	default:
		log.Panicf("unsupported record ID lookup type: %T", r)
		return ""
	}
}

func setRecordID(r libdns.Record, id string) {
	switch v := r.(type) {
	case *addressRecord:
		v.RecordID = id
	case *cnameRecord:
		v.RecordID = id
	case *txtRecord:
		v.RecordID = id
	case libdns.RR:
		// You cannot assign an ID to libdns.RR (immutable). Log or ignore.
		log.Printf("setRecordID: skipping unsupported type %T (libdns.RR)", r)
	default:
		log.Printf("setRecordID: unknown record type %T", r)
	}
}
