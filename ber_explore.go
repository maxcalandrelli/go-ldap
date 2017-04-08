package ldap

import (
	"github.com/mmitton/asn1-ber"
)

func Access(p *ber.Packet, path []int) *ber.Packet {
	for _, index := range path {
		if p == nil || index >= len(p.Children) {
			return nil
		}
		p = p.Children[index]
	}
	return p
}

func AccessUniversal(p *ber.Packet, path []int, defval interface{}) interface{} {
	if p = Access(p, path); p != nil && p.ClassType == ber.ClassUniversal {
		return p.Value
	}
	return defval
}

func GetBool(p *ber.Packet, path []int) bool {
	return AccessUniversal(p, path, false).(bool)
}

func GetString(p *ber.Packet, path []int) string {
	return AccessUniversal(p, path, "").(string)
}

func GetInt(p *ber.Packet, path []int) uint64 {
	return AccessUniversal(p, path, uint64(0)).(uint64)
}

func GetFloat(p *ber.Packet, path []int) float64 {
	return AccessUniversal(p, path, float64(0)).(float64)
}

func GetLDAPResultCode(p *ber.Packet) (code uint8, description string) {
	if p = Access(p, []int{1}); p != nil {
		return uint8(GetInt(p, []int{0})), GetString(p, []int{2})
	}
	return ErrorNetwork, "Invalid packet format"
}
