// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// File contains a filter compiler/decompiler
package ldap

import (
	"errors"
	"fmt"
	"strings"

	"github.com/mmitton/asn1-ber"
)

const (
	FilterAnd             = 0
	FilterOr              = 1
	FilterNot             = 2
	FilterEqualityMatch   = 3
	FilterSubstrings      = 4
	FilterGreaterOrEqual  = 5
	FilterLessOrEqual     = 6
	FilterPresent         = 7
	FilterApproxMatch     = 8
	FilterExtensibleMatch = 9
)

var FilterMap = map[uint64]string{
	FilterAnd:             "And",
	FilterOr:              "Or",
	FilterNot:             "Not",
	FilterEqualityMatch:   "Equality Match",
	FilterSubstrings:      "Substrings",
	FilterGreaterOrEqual:  "Greater Or Equal",
	FilterLessOrEqual:     "Less Or Equal",
	FilterPresent:         "Present",
	FilterApproxMatch:     "Approx Match",
	FilterExtensibleMatch: "Extensible Match",
}

const (
	FilterSubstringsInitial = 0
	FilterSubstringsAny     = 1
	FilterSubstringsFinal   = 2
)

var FilterSubstringsMap = map[uint64]string{
	FilterSubstringsInitial: "Substrings Initial",
	FilterSubstringsAny:     "Substrings Any",
	FilterSubstringsFinal:   "Substrings Final",
}

func CompileFilter(filter string) (*ber.Packet, error) {
	if len(filter) == 0 || filter[0] != '(' {
		return nil, NewError(ErrorFilterCompile, errors.New("Filter does not start with an '('"))
	}
	packet, pos, err := compileFilter(filter, 1)
	if err != nil {
		return nil, err
	}
	if pos != len(filter) {
		return nil, NewError(ErrorFilterCompile, errors.New("Finished compiling filter with extra at end.\n"+fmt.Sprint(filter[pos:])))
	}
	return packet, nil
}

func DecompileFilter(packet *ber.Packet) (ret string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = NewError(ErrorFilterDecompile, errors.New("Error decompiling filter"))
		}
	}()
	ret = "("
	err = nil
	child_str := ""

	switch packet.Tag {
	case FilterAnd:
		ret += "&"
		for _, child := range packet.Children {
			child_str, err = DecompileFilter(child)
			if err != nil {
				return
			}
			ret += child_str
		}
	case FilterOr:
		ret += "|"
		for _, child := range packet.Children {
			child_str, err = DecompileFilter(child)
			if err != nil {
				return
			}
			ret += child_str
		}
	case FilterNot:
		ret += "!"
		child_str, err = DecompileFilter(packet.Children[0])
		if err != nil {
			return
		}
		ret += child_str

	case FilterSubstrings:
		ret += ber.DecodeString(packet.Children[0].Data.Bytes())
		ret += "="
		switch packet.Children[1].Children[0].Tag {
		case FilterSubstringsInitial:
			ret += ber.DecodeString(packet.Children[1].Children[0].Data.Bytes()) + "*"
		case FilterSubstringsAny:
			ret += "*" + ber.DecodeString(packet.Children[1].Children[0].Data.Bytes()) + "*"
		case FilterSubstringsFinal:
			ret += "*" + ber.DecodeString(packet.Children[1].Children[0].Data.Bytes())
		}
	case FilterEqualityMatch:
		ret += ber.DecodeString(packet.Children[0].Data.Bytes())
		ret += "="
		ret += ber.DecodeString(packet.Children[1].Data.Bytes())
	case FilterGreaterOrEqual:
		ret += ber.DecodeString(packet.Children[0].Data.Bytes())
		ret += ">="
		ret += ber.DecodeString(packet.Children[1].Data.Bytes())
	case FilterLessOrEqual:
		ret += ber.DecodeString(packet.Children[0].Data.Bytes())
		ret += "<="
		ret += ber.DecodeString(packet.Children[1].Data.Bytes())
	case FilterPresent:
		ret += ber.DecodeString(packet.Children[0].Data.Bytes())
		ret += "=*"
	case FilterApproxMatch:
		ret += ber.DecodeString(packet.Children[0].Data.Bytes())
		ret += "~="
		ret += ber.DecodeString(packet.Children[1].Data.Bytes())
	}

	ret += ")"
	return
}

func compileFilterSet(filter string, pos int, parent *ber.Packet) (int, error) {
	for pos < len(filter) && filter[pos] == '(' {
		child, new_pos, err := compileFilter(filter, pos+1)
		if err != nil {
			return pos, err
		}
		pos = new_pos
		parent.AppendChild(child)
	}
	if pos == len(filter) {
		return pos, NewError(ErrorFilterCompile, errors.New("Unexpected end of filter"))
	}

	return pos + 1, nil
}

func compileFilter(filter string, pos int) (p *ber.Packet, new_pos int, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = NewError(ErrorFilterCompile, errors.New("Error compiling filter"))
		}
	}()
	p = nil
	new_pos = pos
	err = nil

	switch filter[pos] {
	case '(':
		p, new_pos, err = compileFilter(filter, pos+1)
		new_pos++
		return
	case '&':
		p = ber.Encode(ber.ClassContext, ber.TypeConstructed, FilterAnd, nil, FilterMap[FilterAnd])
		new_pos, err = compileFilterSet(filter, pos+1, p)
		return
	case '|':
		p = ber.Encode(ber.ClassContext, ber.TypeConstructed, FilterOr, nil, FilterMap[FilterOr])
		new_pos, err = compileFilterSet(filter, pos+1, p)
		return
	case '!':
		p = ber.Encode(ber.ClassContext, ber.TypeConstructed, FilterNot, nil, FilterMap[FilterNot])
		var child *ber.Packet
		child, new_pos, err = compileFilter(filter, pos+1)
		p.AppendChild(child)
		return
	default:
		attribute := ""
		condition := ""
		for new_pos < len(filter) && filter[new_pos] != ')' {
			switch {
			case p != nil:
				condition += fmt.Sprintf("%c", filter[new_pos])
			case filter[new_pos] == '=':
				p = ber.Encode(ber.ClassContext, ber.TypeConstructed, FilterEqualityMatch, nil, FilterMap[FilterEqualityMatch])
			case filter[new_pos] == '>' && filter[new_pos+1] == '=':
				p = ber.Encode(ber.ClassContext, ber.TypeConstructed, FilterGreaterOrEqual, nil, FilterMap[FilterGreaterOrEqual])
				new_pos++
			case filter[new_pos] == '<' && filter[new_pos+1] == '=':
				p = ber.Encode(ber.ClassContext, ber.TypeConstructed, FilterLessOrEqual, nil, FilterMap[FilterLessOrEqual])
				new_pos++
			case filter[new_pos] == '~' && filter[new_pos+1] == '=':
				p = ber.Encode(ber.ClassContext, ber.TypeConstructed, FilterApproxMatch, nil, FilterMap[FilterLessOrEqual])
				new_pos++
			case p == nil:
				attribute += fmt.Sprintf("%c", filter[new_pos])
			}
			new_pos++
		}
		if new_pos == len(filter) {
			err = NewError(ErrorFilterCompile, errors.New("Unexpected end of filter"))
			return
		}
		if p == nil {
			err = NewError(ErrorFilterCompile, errors.New("Error parsing filter"))
			return
		}
		p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, attribute, "Attribute"))
		if p.Tag == FilterEqualityMatch {
			components := strings.Split(condition, "*")
			if len(components) > 1 {
				p.Description = FilterMap[uint64(p.Tag)]
				seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Substrings")
				for i, c := range components {
					if len(c) > 0 {
						switch {
						case i == len(components)-1:
							// Final
							seq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimative, FilterSubstringsFinal, c[:], "Final Substring"))
							p.Tag = FilterSubstrings
						case i == 0:
							// Initial
							seq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimative, FilterSubstringsInitial, c[:], "Initial Substring"))
							p.Tag = FilterSubstrings
						default:
							// Any
							seq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimative, FilterSubstringsAny, c[:], "Any Substring"))
							p.Tag = FilterSubstrings
						}
					}
				}
				if p.Tag == FilterSubstrings {
					p.AppendChild(seq)
				}
			}
		}
		if p.Tag == FilterEqualityMatch {
			if condition == "*" {
				p.Tag = FilterPresent
				p = ber.Encode(ber.ClassContext, ber.TypePrimative, FilterPresent, nil, FilterMap[FilterPresent])
				p.Data.WriteString(attribute)
			} else {
				p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, condition, "Condition"))
			}
		}
		p.Description = FilterMap[uint64(p.Tag)]
		new_pos++
		return
	}
	err = NewError(ErrorFilterCompile, errors.New("Reached end of filter without closing parens"))
	return
}
