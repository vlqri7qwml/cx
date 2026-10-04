/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2026 CXProxy. All Rights Reserved.
 *
 * permitSelf 的结构沿用 wireguard-windows 的 permitWireGuardService（MIT），
 * 区别是取不到服务 SID 时退化为仅按 exe 路径放行；
 * permitPrivateNetworks 为 CXProxy 新增。
 */

package firewall

import (
	"net/netip"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// permitSelf 放行 CXProxy 自身的全部流量。
//
// 判据有两条：
//  1. ALE_APP_ID 等于当前可执行文件路径；
//  2. ALE_USER_ID 等于当前进程的服务 SID。
//
// 第二条很关键：同一个 cxproxy.exe 以普通用户身份启动的托盘进程不满足它，
// 因此托盘拿不到绕过断网保护的直连能力，只能通过命名管道请求服务办事。
// 若当前进程不是服务（例如管理员在控制台直接执行子命令），取不到服务 SID，
// 此时退化为仅按 exe 路径放行。
func permitSelf(session uintptr, baseObjects *baseObjects, weight uint8) error {
	appID, err := getCurrentProcessAppID()
	if err != nil {
		return wrapErr(err)
	}
	defer fwpmFreeMemory0(unsafe.Pointer(&appID))

	conditions := make([]wtFwpmFilterCondition0, 1, 2)
	conditions[0] = wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_ALE_APP_ID,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_BYTE_BLOB_TYPE,
			value: uintptr(unsafe.Pointer(appID)),
		},
	}

	var sdBlob wtFwpByteBlob
	sd, sdErr := getCurrentProcessSecurityDescriptor()
	if sdErr == nil {
		sdBlob = wtFwpByteBlob{sd.Length(), (*byte)(unsafe.Pointer(sd))}
		conditions = append(conditions, wtFwpmFilterCondition0{
			fieldKey:  cFWPM_CONDITION_ALE_USER_ID,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_SECURITY_DESCRIPTOR_TYPE,
				value: uintptr(unsafe.Pointer(&sdBlob)),
			},
		})
	}

	filter := wtFwpmFilter0{
		providerKey: &baseObjects.provider,
		subLayerKey: baseObjects.filters,
		weight:      filterWeight(weight),
		// CLEAR_ACTION_RIGHT：不允许其他筛选器覆盖这条放行，
		// 否则第三方安全软件可能把代理自身的出网也挡掉，导致整机彻底失联。
		flags:               cFWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
		numFilterConditions: uint32(len(conditions)),
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions[0])),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	layers := []struct {
		name  string
		layer windows.GUID
	}{
		{"Permit unrestricted outbound traffic for CXProxy service (IPv4)", cFWPM_LAYER_ALE_AUTH_CONNECT_V4},
		{"Permit unrestricted inbound traffic for CXProxy service (IPv4)", cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4},
		{"Permit unrestricted outbound traffic for CXProxy service (IPv6)", cFWPM_LAYER_ALE_AUTH_CONNECT_V6},
		{"Permit unrestricted inbound traffic for CXProxy service (IPv6)", cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6},
	}

	filterID := uint64(0)
	for _, l := range layers {
		displayData, err := createWtFwpmDisplayData0(l.name, "")
		if err != nil {
			return wrapErr(err)
		}
		filter.displayData = *displayData
		filter.layerKey = l.layer
		if err := addFilter(session, &filter, 0, &filterID); err != nil {
			return wrapErr(err)
		}
	}

	runtime.KeepAlive(conditions)
	runtime.KeepAlive(sdBlob)
	runtime.KeepAlive(sd)
	return nil
}

// permitPrivateNetworks 放行局域网，对应设置项「断网时允许局域网」。
//
// 注意这里只按对端地址放行，不区分进程：局域网本身到不了公网，
// 因此不存在真实 IP 泄露的风险。
func permitPrivateNetworks(session uintptr, baseObjects *baseObjects, weight uint8) error {
	filter := wtFwpmFilter0{
		providerKey: &baseObjects.provider,
		subLayerKey: baseObjects.filters,
		weight:      filterWeight(weight),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}
	filterID := uint64(0)

	// 让掩码结构体活到 fwpmFilterAdd0 调用之后。
	v4Masks := make([]wtFwpV4AddrAndMask, len(privateV4))
	v6Masks := make([]wtFwpV6AddrAndMask, len(privateV6))

	for i, p := range privateV4 {
		v4Masks[i] = v4AddrMask(p)
		condition := wtFwpmFilterCondition0{
			fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_V4_ADDR_MASK,
				value: uintptr(unsafe.Pointer(&v4Masks[i])),
			},
		}
		filter.numFilterConditions = 1
		filter.filterCondition = &condition

		for _, l := range []struct {
			name  string
			layer windows.GUID
		}{
			{"Permit outbound LAN " + p.String(), cFWPM_LAYER_ALE_AUTH_CONNECT_V4},
			{"Permit inbound LAN " + p.String(), cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4},
		} {
			displayData, err := createWtFwpmDisplayData0(l.name, "")
			if err != nil {
				return wrapErr(err)
			}
			filter.displayData = *displayData
			filter.layerKey = l.layer
			if err := addFilter(session, &filter, 0, &filterID); err != nil {
				return wrapErr(err)
			}
		}
		runtime.KeepAlive(condition)
	}

	for i, p := range privateV6 {
		v6Masks[i] = v6AddrMask(p)
		condition := wtFwpmFilterCondition0{
			fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_V6_ADDR_MASK,
				value: uintptr(unsafe.Pointer(&v6Masks[i])),
			},
		}
		filter.numFilterConditions = 1
		filter.filterCondition = &condition

		for _, l := range []struct {
			name  string
			layer windows.GUID
		}{
			{"Permit outbound LAN " + p.String(), cFWPM_LAYER_ALE_AUTH_CONNECT_V6},
			{"Permit inbound LAN " + p.String(), cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6},
		} {
			displayData, err := createWtFwpmDisplayData0(l.name, "")
			if err != nil {
				return wrapErr(err)
			}
			filter.displayData = *displayData
			filter.layerKey = l.layer
			if err := addFilter(session, &filter, 0, &filterID); err != nil {
				return wrapErr(err)
			}
		}
		runtime.KeepAlive(condition)
	}

	runtime.KeepAlive(v4Masks)
	runtime.KeepAlive(v6Masks)
	return nil
}

// v4AddrMask 把前缀填进 WFP 的 FWP_V4_ADDR_AND_MASK 结构。
func v4AddrMask(p netip.Prefix) wtFwpV4AddrAndMask {
	addr, mask := prefixToV4(p)
	return wtFwpV4AddrAndMask{addr, mask}
}

// v6AddrMask 把前缀填进 FWP_V6_ADDR_AND_MASK 结构。
func v6AddrMask(p netip.Prefix) wtFwpV6AddrAndMask {
	addr, prefixLen := prefixToV6(p)
	return wtFwpV6AddrAndMask{addr, prefixLen}
}
