package expr

import (
	"fmt"

	"github.com/google/nftables/binaryutil"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// CtID is for the ct id expression.
type CtID struct {
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
	return fmt.Errorf("unimplemented.")
}
