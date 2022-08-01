package expr

import (
	"encoding/binary"

	"github.com/google/nftables/binaryutil"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// CtID is for the ct id expression.  See:
// https://github.com/untangle/mfw_feeds/blob/f8b948b8a3c86cc20e921c95d5c9a6de3a7abf70/nftables/patches/999-nftables-Add-dict.patch#L711.
// There is a different expression type for ctid so we need this
// object.
type CtID struct {
	// The destination register of the ct id.
	Register uint32
}

func (e *CtID) marshal(fam byte) ([]byte, error) {
	exprData, err := netlink.MarshalAttributes(
		[]netlink.Attribute{
			{Type: unix.NFTA_CT_DREG, Data: binaryutil.BigEndian.PutUint32(e.Register)},
		})
	if err != nil {
		return nil, err
	}
	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte("ctid\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA,
			Data: exprData,
		},
	})
}
func (e *CtID) unmarshal(fam byte, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_CT_DREG:
			e.Register = ad.Uint32()
		}
	}
	return ad.Err()
}
