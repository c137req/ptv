package formats

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Velocidex/ordereddict"
	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
	"www.velocidex.com/golang/evtx"
)

type _evtx struct{}

func init() { module.Register(&_evtx{}) }

func (e *_evtx) Name() string { return "evtx" }

func (e *_evtx) Parse(raw []byte) (*ir.Dataset, error) {
	reader := bytes.NewReader(raw)
	chunks, err := evtx.GetChunks(reader)
	if err != nil {
		return nil, fmt.Errorf("evtx: %w", err)
	}

	var records []ir.Record
	for _, chunk := range chunks {
		evtRecords, err := chunk.Parse(0)
		if err != nil {
			continue
		}

		for _, rec := range evtRecords {
			eventDict, ok := rec.Event.(*ordereddict.Dict)
			if !ok {
				continue
			}

			r := ir.Record{PTVID: ir.NewPTVID(), Extra: map[string]any{}}

			// get the Event wrapper
			eventObj, ok := eventDict.Get("Event")
			if !ok {
				continue
			}
			event, ok := eventObj.(*ordereddict.Dict)
			if !ok {
				continue
			}

			// system fields
			if v, ok := ordereddict.GetString(event, "System.Computer"); ok {
				r.Domain = v
			}
			if v, ok := ordereddict.GetInt(event, "System.EventID.Value"); ok {
				r.Extra["event_id"] = fmt.Sprintf("%d", v)
			}
			if v, ok := ordereddict.GetString(event, "System.Channel"); ok {
				r.Extra["channel"] = v
			}
			if v, ok := ordereddict.GetString(event, "System.Provider.Name"); ok {
				r.Extra["provider"] = v
			}

			// extract credential-relevant fields from EventData or UserData
			_evtx_extract_data(event, &r, "EventData")
			_evtx_extract_data(event, &r, "UserData")

			if len(r.Extra) == 0 {
				r.Extra = nil
			}
			records = append(records, r)
		}
	}

	cols := _detect_columns(records)
	conf := map[string]float64{}
	for _, c := range cols {
		conf[c] = 0.7
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "evtx",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

// _evtx_extract_data walks EventData or UserData sections for credential fields
func _evtx_extract_data(event *ordereddict.Dict, r *ir.Record, section string) {
	dataObj, ok := event.Get(section)
	if !ok {
		return
	}

	dataDict, ok := dataObj.(*ordereddict.Dict)
	if !ok {
		return
	}

	// walk all keys in the section (may be nested one level for UserData)
	_evtx_walk_dict(dataDict, r)
}

func _evtx_walk_dict(d *ordereddict.Dict, r *ir.Record) {
	for _, key := range d.Keys() {
		val, _ := d.Get(key)

		// if nested dict, recurse
		if nested, ok := val.(*ordereddict.Dict); ok {
			_evtx_walk_dict(nested, r)
			continue
		}

		lower := strings.ToLower(key)
		str := fmt.Sprintf("%v", val)
		if str == "" || str == "<nil>" {
			continue
		}

		switch {
		case strings.Contains(lower, "username") || strings.Contains(lower, "accountname"):
			if r.Username == "" {
				r.Username = str
			}
		case strings.Contains(lower, "domainname"):
			if r.Extra == nil {
				r.Extra = map[string]any{}
			}
			r.Extra["subject_domain"] = str
		case strings.Contains(lower, "ipaddress"):
			if r.IP == "" && str != "-" && str != "::1" {
				r.IP = str
			}
		case strings.Contains(lower, "ipport"):
			if r.Extra == nil {
				r.Extra = map[string]any{}
			}
			r.Extra["source_port"] = str
		case strings.Contains(lower, "logontype"):
			if r.Extra == nil {
				r.Extra = map[string]any{}
			}
			r.Extra["logon_type"] = str
		case strings.Contains(lower, "usersid") || strings.Contains(lower, "targetsid"):
			if r.Extra == nil {
				r.Extra = map[string]any{}
			}
			r.Extra["sid"] = str
		}
	}
}

func (e *_evtx) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	for _, r := range ds.Records {
		obj := map[string]any{}
		if r.Username != "" {
			obj["SubjectUserName"] = r.Username
		}
		if r.Domain != "" {
			obj["Computer"] = r.Domain
		}
		if r.IP != "" {
			obj["IpAddress"] = r.IP
		}
		if r.Extra != nil {
			if eid, ok := r.Extra["event_id"].(string); ok {
				obj["EventID"] = eid
			}
			if ch, ok := r.Extra["channel"].(string); ok {
				obj["Channel"] = ch
			}
			if sd, ok := r.Extra["subject_domain"].(string); ok {
				obj["SubjectDomainName"] = sd
			}
			if sid, ok := r.Extra["sid"].(string); ok {
				obj["SubjectUserSid"] = sid
			}
		}

		data, err := json.Marshal(obj)
		if err != nil {
			continue
		}
		b.Write(data)
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}
