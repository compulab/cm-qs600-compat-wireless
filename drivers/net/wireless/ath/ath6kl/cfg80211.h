/*
 * Copyright (c) 2011 Atheros Communications Inc.
 * Copyright (c) 2011-2012 Qualcomm Atheros, Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef ATH6KL_CFG80211_H
#define ATH6KL_CFG80211_H

enum ath6kl_cfg_suspend_mode {
	ATH6KL_CFG_SUSPEND_DEEPSLEEP,
	ATH6KL_CFG_SUSPEND_CUTPOWER,
	ATH6KL_CFG_SUSPEND_WOW,
	ATH6KL_CFG_SUSPEND_SCHED_SCAN,
};

typedef enum {
	ATH6KL_MODE_11A        = 0,   /* 11a Mode */
	ATH6KL_MODE_11G        = 1,   /* 11b/g Mode */
	ATH6KL_MODE_11B        = 2,   /* 11b Mode */
	ATH6KL_MODE_11GONLY    = 3,   /* 11g only Mode */
	ATH6KL_MODE_11NA_HT20   = 4,  /* 11a HT20 mode */
	ATH6KL_MODE_11NG_HT20   = 5,  /* 11g HT20 mode */
	ATH6KL_MODE_11NA_HT40   = 6,  /* 11a HT40 mode */
	ATH6KL_MODE_11NG_HT40   = 7,  /* 11g HT40 mode */
	ATH6KL_MODE_UNKNOWN    = 8,
	ATH6KL_MODE_MAX        = 8
} WLAN_ATH6KL_PHY_MODE;

enum {
	ATH6KL_HTINFO_EXTOFFSET_NA    = 0,   /* 0  no extension channel is present */
	ATH6KL_HTINFO_EXTOFFSET_ABOVE = 1,   /* +1 extension channel above control channel */
	ATH6KL_HTINFO_EXTOFFSET_UNDEF = 2,   /* -2 undefined */
	ATH6KL_HTINFO_EXTOFFSET_BELOW = 3    /* -1 extension channel below control channel*/
};


struct net_device *ath6kl_interface_add(struct ath6kl *ar, char *name,
					enum nl80211_iftype type,
					u8 fw_vif_idx, u8 nw_type);
void ath6kl_cfg80211_ch_switch_notify(struct ath6kl_vif *vif, int freq,
				      u8 sec_ch, u8 phymode);
void ath6kl_cfg80211_scan_complete_event(struct ath6kl_vif *vif, bool aborted);

void ath6kl_cfg80211_connect_event(struct ath6kl_vif *vif, u16 channel,
				   u8 *bssid, u16 listen_intvl,
				   u16 beacon_intvl,
				   enum network_type nw_type,
				   u8 beacon_ie_len, u8 assoc_req_len,
				   u8 assoc_resp_len, u8 *assoc_info);

void ath6kl_cfg80211_disconnect_event(struct ath6kl_vif *vif, u8 reason,
				      u8 *bssid, u8 assoc_resp_len,
				      u8 *assoc_info, u16 proto_reason);

void ath6kl_cfg80211_tkip_micerr_event(struct ath6kl_vif *vif, u8 keyid,
				     bool ismcast);

int ath6kl_cfg80211_suspend(struct ath6kl *ar,
			    enum ath6kl_cfg_suspend_mode mode,
			    struct cfg80211_wowlan *wow);

int ath6kl_cfg80211_resume(struct ath6kl *ar);

void ath6kl_cfg80211_vif_cleanup(struct ath6kl_vif *vif);

void ath6kl_cfg80211_stop(struct ath6kl_vif *vif);
void ath6kl_cfg80211_stop_all(struct ath6kl *ar);

int ath6kl_cfg80211_init(struct ath6kl *ar);
void ath6kl_cfg80211_cleanup(struct ath6kl *ar);

struct ath6kl *ath6kl_cfg80211_create(void);
void ath6kl_cfg80211_destroy(struct ath6kl *ar);
/* TODO: remove this once ath6kl_vif_cleanup() is moved to cfg80211.c */
void ath6kl_cfg80211_sta_bmiss_enhance(struct ath6kl_vif *vif, bool enable);

#endif /* ATH6KL_CFG80211_H */
