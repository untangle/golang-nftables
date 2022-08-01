package expr

import (
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestCtid(t *testing.T) {
	t.Parallel()
	id := CtID{
		Register: 1,
	}

	data, err := id.marshal(0)
	if err != nil {
		t.Fatalf("marshal error: %+v", err)
	}

	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		t.Fatalf("NewAttributeDecoder() error: %+v", err)
	}

	ad.ByteOrder = binary.BigEndian
	unmarshalled := CtID{}
	for ad.Next() {
		if ad.Type() == unix.NFTA_EXPR_DATA {
			if err := unmarshalled.unmarshal(0, ad.Bytes()); err != nil {
				t.Errorf("unmarshal error: %+v", err)
				break
			}
		}
	}

	if !reflect.DeepEqual(id, unmarshalled) {
		t.Fatalf("original %+v and recovered %+v ctids are different", id, unmarshalled)
	}

}
