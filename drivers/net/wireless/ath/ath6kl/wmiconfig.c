/*
 * Copyright (c) 2010-2011 Atheros Communications Inc.
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
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


#include <linux/printk.h>
#include <asm/unaligned.h>

#include "core.h"
#include "cfg80211.h"
#include "debug.h"
#include "hif-ops.h"
#include "testmode.h"
#include "wmiconfig.h"
#include "wmi.h"

#include <net/netlink.h>

enum ath6kl_tm_attr {
	__ATH6KL_TM_ATTR_INVALID	= 0,
	ATH6KL_TM_ATTR_CMD		= 1,
	ATH6KL_TM_ATTR_DATA		= 2,

	/* keep last */
	__ATH6KL_TM_ATTR_AFTER_LAST,
	ATH6KL_TM_ATTR_MAX		= __ATH6KL_TM_ATTR_AFTER_LAST - 1,
};

enum ath6kl_tm_cmd {
	ATH6KL_TM_CMD_TCMD		= 0,
	ATH6KL_TM_CMD_RX_REPORT		= 1,	/* not used anymore */
	ATH6KL_TM_CMD_WMI_CMD		= 0xF000,
};

#define AP_ACS_NONE AP_ACS_POLICY_MAX
#define ATH6KL_AP_APPLY_ACS_DISABLED 0
#define ATH6KL_AP_APPLY_ACS_ENABLED  1

#define ATH6KL_AP_ACS_RESET       0x00
#define ATH6KL_AP_ACS_IN_PROGRESS 0x01
#define ATH6KL_AP_ACS_COMPLETED   0x02
#define ATH6KL_AP_ACS_NOT_NEEDED  0x04

struct app_lte_coex_wwan_data_t {
	uint32_t cmd;

	uint32_t band_info_valid;
	uint32_t ul_freq;
	uint32_t ul_bw;
	uint32_t dl_freq;
	uint32_t dl_bw;

	uint32_t tdd_info_valid;
	uint32_t fr_offset;
	uint32_t tdd_cfg;
	uint32_t sub_fr_cfg;
	uint32_t ul_cfg;
	uint32_t dl_cfg;

	uint32_t off_period_valid;
	uint32_t off_period;
};

#define GET_LTE_COEX_MODE(lte_coex_mode) ((lte_coex_mode == \
			LTE_COEX_MODE_CHANNEL_AVOIDANCE) ? \
			"CA" : (lte_coex_mode == LTE_COEX_MODE_3WIRE) ? \
			"3W" : (lte_coex_mode == \
			LTE_COEX_MODE_PWR_BACKOFF) ? "PB" : "XX")

#define GET_ATH6KL_LTE_COEX_WWAN_MODE(wwan_mode) (\
			(wwan_mode == LTE_COEX_WWAN_MODE_TDD_CONFIG) ? \
			"TDD" : (wwan_mode == \
			LTE_COEX_WWAN_MODE_FDD_CONFIG) ? \
			"FDD" : "XXX")

#define GET_ATH6KL_LTE_COEX_WWAN_STATE(wwan_state) (\
				(wwan_state == \
				LTE_COEX_WWAN_STATE_CONNECTED) ? \
				"CNT" : \
				(wwan_state == \
				LTE_COEX_WWAN_STATE_IDLE) ? \
				"IDL" : "XXX")

#define GET_ACS_POLICY(acs)	((acs == AP_ACS_NORMAL) ? "1&6&11" : \
				(acs == AP_ACS_DISABLE_CH11) ? "1&6" : \
				(acs == AP_ACS_DISABLE_CH1) ? "6&11" : \
				(acs == AP_ACS_DISABLE_CH1_6) ? "11" : \
					(acs == AP_ACS_NONE) ? "X" : \
					"AP_ACS_INCLUDE_CH13")

#define GET_ATH6KL_WWAN_BAND(band) ((band & ATH6KL_WWAN_B40) ? "TDD-B40" : \
				(band & ATH6KL_WWAN_B41) ? "TDD-B41" : \
				(band & ATH6KL_WWAN_B7) ? "FDD_B7" : \
						"NON-INF-BAND")

/*TDD B40*/
#define ATH6KL_WWAN_FREQ_2300 2300
#define ATH6KL_WWAN_FREQ_2350 2350
#define ATH6KL_WWAN_FREQ_2370 2370
#define ATH6KL_WWAN_FREQ_2380 2380
#define ATH6KL_WWAN_FREQ_2401 2401

/*TDD B41 | FDD B7*/
#define ATH6KL_WWAN_FREQ_2496 2496
#define ATH6KL_WWAN_FREQ_2570 2570

/*TDD B38*/
#define ATH6KL_WWAN_FREQ_2570 2570
#define ATH6KL_WWAN_FREQ_2620 2620

#define ATH6KL_WWAN_TDD 0xF0
#define ATH6KL_WWAN_B40 0x80
#define ATH6KL_WWAN_B41 0x40
#define ATH6KL_WWAN_B38 0x20

#define ATH6KL_WWAN_FDD 0x0F
#define ATH6KL_WWAN_B7	 0x08
#define ATH6KL_WWAN_B20	 0x04

#define ATH6KL_WWAN_BAND 0xFF

#define CH1 2412
#define CH2 2417
#define CH3 2422
#define CH4 2427
#define CH5 2432
#define CH6 2437
#define CH7 2442
#define CH8 2447
#define CH9 2452
#define CH10 2457
#define CH11 2462
#define CH12 2467
#define CH13 2472
#define CH14 2484


#define CHAN1 BIT(0)
#define CHAN2 BIT(1)
#define CHAN3 BIT(2)
#define CHAN4 BIT(3)
#define CHAN5 BIT(4)
#define CHAN6 BIT(5)
#define CHAN7 BIT(6)
#define CHAN8 BIT(7)
#define CHAN9 BIT(8)
#define CHAN10 BIT(9)
#define CHAN11 BIT(10)
#define CHAN12 BIT(11)
#define CHAN13 BIT(12)

#define  LTE_COEX_REF_TDD_ROWS 8
#define LTE_COEX_REF_FDD_ROWS 57
struct _lte_coex_chk {
	int wwan_min_freq;
	int	wwan_max_freq;
	int wwan_bw;
	int wlan_min_freq;
	int wlan_max_freq;
	uint8_t	sta_lte_coex_mode;
	uint8_t ap_lte_coex_mode;
	u32 acs_chan_mask;
	bool    apply_acs;
	uint8_t wwan_band;
	uint8_t no_of_entry;
};

struct _lte_coex_chk lte_coex_tdd_lookup_table[LTE_COEX_REF_TDD_ROWS] = {
/* wwan_min_freq  wwan_max_freq    wlan_freq    sta_lte_coex_mode
 *      ap_lte_coex_mode                        ap_acs
 *	apply_acs					wwan_band
 */
{ATH6KL_WWAN_FREQ_2300,  ATH6KL_WWAN_FREQ_2350, 0, CH1, CH4,
						LTE_COEX_MODE_3WIRE,
	LTE_COEX_MODE_CHANNEL_AVOIDANCE,	(CHAN5 | CHAN6 | CHAN7 | CHAN8 | CHAN9 | CHAN10 | CHAN11 | CHAN12 | CHAN13),
	ATH6KL_AP_APPLY_ACS_ENABLED,			ATH6KL_WWAN_B40, 2},

{ATH6KL_WWAN_FREQ_2300,  ATH6KL_WWAN_FREQ_2350, 0, CH5, CH14,
						LTE_COEX_MODE_DISABLED,
	LTE_COEX_MODE_DISABLED,			(CHAN5 | CHAN6 | CHAN7 | CHAN8 | CHAN9 | CHAN10 | CHAN11 | CHAN12 | CHAN13),
	ATH6KL_AP_APPLY_ACS_DISABLED,			ATH6KL_WWAN_B40, 2},

{ATH6KL_WWAN_FREQ_2350,  ATH6KL_WWAN_FREQ_2370, 0, CH1, CH6,
						LTE_COEX_MODE_3WIRE,
	LTE_COEX_MODE_CHANNEL_AVOIDANCE,	(CHAN7 | CHAN8 | CHAN9 | CHAN10 | CHAN11 | CHAN12 | CHAN13),
	ATH6KL_AP_APPLY_ACS_ENABLED,			ATH6KL_WWAN_B40, 2},

{ATH6KL_WWAN_FREQ_2350,  ATH6KL_WWAN_FREQ_2370, 0, CH7, CH14,
						LTE_COEX_MODE_DISABLED,
	LTE_COEX_MODE_DISABLED,			(CHAN7 | CHAN8 | CHAN9 | CHAN10 | CHAN11 | CHAN12 | CHAN13),
	ATH6KL_AP_APPLY_ACS_DISABLED,		ATH6KL_WWAN_B40, 2},

{ATH6KL_WWAN_FREQ_2370,  ATH6KL_WWAN_FREQ_2401, 0, CH1, CH9,
						LTE_COEX_MODE_PWR_BACKOFF,
	LTE_COEX_MODE_PWR_BACKOFF,		(CHAN10 | CHAN11 | CHAN12 | CHAN13),
	ATH6KL_AP_APPLY_ACS_ENABLED,			ATH6KL_WWAN_B40, 2},

{ATH6KL_WWAN_FREQ_2370,  ATH6KL_WWAN_FREQ_2401, 0, CH10, CH14,
						LTE_COEX_MODE_PWR_BACKOFF,
	LTE_COEX_MODE_PWR_BACKOFF,		(CHAN10 | CHAN11 | CHAN12 | CHAN13),
	ATH6KL_AP_APPLY_ACS_DISABLED,			ATH6KL_WWAN_B40, 2},


/* band 41 tdd */
{2496,  2691, 0, CH1, CH9,
						LTE_COEX_MODE_3WIRE,
	LTE_COEX_MODE_3WIRE,			(CHAN1| CHAN2 | CHAN3 | CHAN4 | CHAN5 | CHAN6 | CHAN7 | CHAN8 | CHAN9),
	ATH6KL_AP_APPLY_ACS_DISABLED,		ATH6KL_WWAN_B41, 2},
{2496,  2691, 0, CH10, CH14,
						LTE_COEX_MODE_3WIRE,
	LTE_COEX_MODE_3WIRE,			(CHAN1| CHAN2 | CHAN3 | CHAN4 | CHAN5 | CHAN6 | CHAN7 | CHAN8 | CHAN9),
	ATH6KL_AP_APPLY_ACS_ENABLED,		ATH6KL_WWAN_B41, 2},

};


/* Coex mode same for FDD B20 and B7 */
struct _lte_coex_chk lte_coex_fdd_lookup_table[LTE_COEX_REF_FDD_ROWS] = {
{2500,  2525, 10, CH1, CH3,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,	(CHAN4 | CHAN5 | CHAN6 | CHAN7 | CHAN8 | CHAN9),
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B7, 3},
{2500,  2525, 10, CH4, CH9,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN4 | CHAN5 | CHAN6 | CHAN7 | CHAN8 | CHAN9),
        ATH6KL_AP_APPLY_ACS_DISABLED,           ATH6KL_WWAN_B7, 3},
{2500,  2525, 10, CH10, CH14,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN4 | CHAN5 | CHAN6 | CHAN7 | CHAN8 | CHAN9),
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B7, 3},

{2525,  2552, 10, CH1, CH8,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,       (CHAN9 | CHAN10 | CHAN11 | CHAN12 | CHAN13),
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B7, 3},
{2525,  2552, 10, CH9, CH13,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN9 | CHAN10 | CHAN11 | CHAN12 | CHAN13),
        ATH6KL_AP_APPLY_ACS_DISABLED,           ATH6KL_WWAN_B7, 3},
{2525,  2552, 10, CH14, CH14,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN9 | CHAN10 | CHAN11 | CHAN12 | CHAN13),
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B7, 3},

{2552,  2562, 10, CH1, CH10,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN11 | CHAN12 | CHAN13),
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B7, 3},
{2552,  2562, 10, CH11, CH13,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN11 | CHAN12 | CHAN13),
        ATH6KL_AP_APPLY_ACS_DISABLED,           ATH6KL_WWAN_B7, 3},
{2552,  2562, 10, CH14, CH14,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN11 | CHAN12 | CHAN13),
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B7, 3},

{2562,  2568, 10, CH1, CH3,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN1 | CHAN2 | CHAN3 | CHAN13),
        ATH6KL_AP_APPLY_ACS_DISABLED,           ATH6KL_WWAN_B7, 4},
{2562,  2568, 10, CH4, CH12,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN1 | CHAN2 | CHAN3 | CHAN13),
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B7, 4},
{2562,  2568, 10, CH13, CH13,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN1 | CHAN2 | CHAN3 | CHAN13),
        ATH6KL_AP_APPLY_ACS_DISABLED,           ATH6KL_WWAN_B7, 4},
{2562,  2568, 10, CH14, CH14,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN1 | CHAN2 | CHAN3 | CHAN13),
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B7, 4},

{2568,  2570, 10, CH1, CH4,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN1 | CHAN2 | CHAN3 | CHAN4),
        ATH6KL_AP_APPLY_ACS_DISABLED,           ATH6KL_WWAN_B7, 2},
{2568,  2570, 10, CH5, CH14,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN1 | CHAN2 | CHAN3 | CHAN4),
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B7, 2},


{2500,  2525, 20, CH1, CH5,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN6 | CHAN7 | CHAN8 | CHAN9),
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B7, 3},
{2500,  2525, 20, CH6, CH9,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN6 | CHAN7 | CHAN8 | CHAN9),
        ATH6KL_AP_APPLY_ACS_DISABLED,           ATH6KL_WWAN_B7, 3},
{2500,  2525, 20, CH10, CH14,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN6 | CHAN7 | CHAN8 | CHAN9),
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B7, 3},

{2525,  2552, 20, CH1, CH10,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN11 | CHAN12 | CHAN13),
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B7, 3},
{2525,  2552, 20, CH11, CH13,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN11 | CHAN12 | CHAN13),
        ATH6KL_AP_APPLY_ACS_DISABLED,           ATH6KL_WWAN_B7, 3},
{2525,  2552, 20, CH14, CH14,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN11 | CHAN12 | CHAN13),
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B7, 3},

{2552,  2562, 20, CH1, CH12,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        CHAN13,
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B7, 3},
{2552,  2562, 20, CH13, CH13,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        CHAN13,
        ATH6KL_AP_APPLY_ACS_DISABLED,           ATH6KL_WWAN_B7, 3},
{2552,  2562, 20, CH14, CH14,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        CHAN13,
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B7, 3},

{2562,  2568, 20, CH1, CH1,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN1 | CHAN13),
        ATH6KL_AP_APPLY_ACS_DISABLED,           ATH6KL_WWAN_B7, 4},
{2562,  2568, 20, CH2, CH12,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN1 | CHAN13),
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B7, 4},
{2562,  2568, 20, CH13, CH13,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN1 | CHAN13),
        ATH6KL_AP_APPLY_ACS_DISABLED,           ATH6KL_WWAN_B7, 4},
{2562,  2568, 20, CH14, CH14,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN1 | CHAN13),
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B7, 4},

{2568,  2570, 20, CH1, CH2,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN1 | CHAN2),
        ATH6KL_AP_APPLY_ACS_DISABLED,           ATH6KL_WWAN_B7, 2},
{2568,  2570, 20, CH3, CH14,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN1 | CHAN2),
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B7, 2},

//B20
{832,  837, 10, CH1, CH4,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN1 | CHAN2 | CHAN3 | CHAN4),
        ATH6KL_AP_APPLY_ACS_DISABLED,           ATH6KL_WWAN_B20, 2},
{832,  837, 10, CH5, CH14,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN1 | CHAN2 | CHAN3 | CHAN4),
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B20, 2},


{837,  844, 10, CH1, CH2,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN3 | CHAN4 | CHAN5 | CHAN6 | CHAN7),
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B20, 3},
{837,  844, 10, CH3, CH7,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN3 | CHAN4 | CHAN5 | CHAN6 | CHAN7),
        ATH6KL_AP_APPLY_ACS_DISABLED,           ATH6KL_WWAN_B20, 3},

{837,  844, 10, CH8, CH14,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN3 | CHAN4 | CHAN5 | CHAN6 | CHAN7),
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B20, 3},

{845,  852, 10, CH1, CH7,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN8 | CHAN9 | CHAN10 | CHAN11 | CHAN12),
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B20, 3},
{845,  852, 10, CH8, CH12,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN8 | CHAN9 | CHAN10 | CHAN11 | CHAN12),
        ATH6KL_AP_APPLY_ACS_DISABLED,           ATH6KL_WWAN_B20, 3},
{845,  852, 10, CH13, CH14,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN8 | CHAN9 | CHAN10 | CHAN11 | CHAN12),
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B20, 3},

{852,  857, 10, CH1, CH2,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN1 | CHAN2 | CHAN11 | CHAN12 | CHAN13),
        ATH6KL_AP_APPLY_ACS_DISABLED,           ATH6KL_WWAN_B20, 4},
{852,  857, 10, CH3, CH10,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN1 | CHAN2 | CHAN11 | CHAN12 | CHAN13),
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B20, 4},
{852,  857, 10, CH11, CH13,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN1 | CHAN2 | CHAN11 | CHAN12 | CHAN13),
        ATH6KL_AP_APPLY_ACS_DISABLED,           ATH6KL_WWAN_B20, 4},
{852,  857, 10, CH14, CH14,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN1 | CHAN2 | CHAN11 | CHAN12 | CHAN13),
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B20, 4},

{857,  862, 10, CH1, CH7,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN1 | CHAN2 | CHAN3 | CHAN4 | CHAN5 | CHAN6 | CHAN7),
        ATH6KL_AP_APPLY_ACS_DISABLED,           ATH6KL_WWAN_B20, 2},
{857,  862, 10, CH8, CH14,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN1 | CHAN2 | CHAN3 | CHAN4 | CHAN5 | CHAN6 | CHAN7),
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B20, 2},



{832,  837, 20, CH1, CH2,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN1 | CHAN2),
        ATH6KL_AP_APPLY_ACS_DISABLED,           ATH6KL_WWAN_B20, 2},
{832,  837, 20, CH3, CH14,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN1 | CHAN2),
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B20, 2},


{837,  844, 20, CH1, CH3,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN4 | CHAN5),
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B20, 3},
{837,  844, 20, CH4, CH5,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN4 | CHAN5),
        ATH6KL_AP_APPLY_ACS_DISABLED,           ATH6KL_WWAN_B20, 3},
{837,  844, 20, CH6, CH14,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN4 | CHAN5),
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B20, 3},

{845,  852, 20, CH1, CH8,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN9 | CHAN10),
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B20, 3},
{845,  852, 20, CH9, CH10,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN9 | CHAN10),
        ATH6KL_AP_APPLY_ACS_DISABLED,           ATH6KL_WWAN_B20, 3},
{845,  852, 20, CH11, CH14,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN9 | CHAN10),
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B20, 3},

{852,  857, 20, CH1, CH11,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN12 | CHAN13),
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B20, 3},
{852,  857, 20, CH12, CH13,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN12 | CHAN13),
        ATH6KL_AP_APPLY_ACS_DISABLED,           ATH6KL_WWAN_B20, 3},
{852,  857, 20, CH14, CH14,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN12 | CHAN13),
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B20, 3},

{857,  862, 20, CH1, CH4,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN1 | CHAN2 | CHAN3 | CHAN4),
        ATH6KL_AP_APPLY_ACS_DISABLED,           ATH6KL_WWAN_B20, 2},
{857,  862, 20, CH5, CH14,
                                                LTE_COEX_MODE_3WIRE,
        LTE_COEX_MODE_CHANNEL_AVOIDANCE,        (CHAN1 | CHAN2 | CHAN3 | CHAN4),
        ATH6KL_AP_APPLY_ACS_ENABLED,           ATH6KL_WWAN_B20, 2},

/* No lte_coex needed for TDD B38
 *{ATH6KL_WWAN_FREQ_2570, ATH6KL_WWAN_FREQ_2620, CH1, CH14,
 *                                              LTE_COEX_MODE_DISABLED,
 *      LTE_COEX_MODE_DISABLED,            AP_ACS_NONE,
 *                                              ATH6KL_WWAN_B38},
 */
};

#define LTE_COEX_TX_PWR_MAX 20
#define ATH6KL_WWAN_LTE_COEX_MAX_CHN 5
#define WLAN_LTE_COEX_2G_MAX_CHN 3
#define SEND_WMI_CMD 1

const int8_t max_tx_pwr_arr_b40[15] = {
/* Table for ATH6KL_WWAN_B40_MAX_CHN * WLAN_LTE_COEX_2G_MAX_CHN */

/*	2310	2330	2350	2370	2390	Other band*/
/*CH1*/	5,	5,	5,	5,	-10,
/*CH6*/	20,	20,	20,	10,	0,
/*CH11*/20,	20,	20,	15,	10};

const int8_t max_tx_pwr_arr_b41[15] = {
/*	2500	2520	2540	2560	2580	Other band */
/*CH1*/  10,	15,	20,	20,	20,
/*CH6*/	 0,	10,	20,	20,	20,
/*CH11*/ -10,	5,	5,	5,	5};

const uint32_t lte_tdd_b40_freq_arr[] = { 2310, 2330, 2350, 2370, 2390};
const uint32_t wlan_acs_ch_freq_arr[] = { CH1, CH6, CH11, 0};

struct sk_buff *ath6kl_wmi_get_buf(u32 size)
{
	struct sk_buff *skb;

	skb = ath6kl_buf_alloc(size);
	if (!skb)
		return NULL;

	skb_put(skb, size);
	if (size)
		memset(skb->data, 0, size);

	return skb;
}

static int ath6kl_lte_coex_calc_txpwr(struct ath6kl *ar, int wlan_freq)
{
	int8_t i, j;
	int8_t *max_tx_pwr_arr;

	if (wlan_freq == 0)
		return LTE_COEX_TX_PWR_MAX;

	if (ar->lte_coex->wwan_band & ATH6KL_WWAN_B40)
		max_tx_pwr_arr = (int8_t *)max_tx_pwr_arr_b40;
	else if (ar->lte_coex->wwan_band & ATH6KL_WWAN_B41)
		max_tx_pwr_arr = (int8_t *)max_tx_pwr_arr_b41;
	else /* for B7 on ul band interferes and other band discard */
		return LTE_COEX_TX_PWR_MAX;

	/* Iterate Table column for wwan channel */
	for (i = 0; i < (ATH6KL_WWAN_LTE_COEX_MAX_CHN - 1); i++) {
		if (!(ar->lte_coex->wwan_freq > lte_tdd_b40_freq_arr[i]))
			break;
	}
	/* Iterate Table row for wlan channel */
	for (j = 0; j < (WLAN_LTE_COEX_2G_MAX_CHN - 1); j++) {
		if (!(wlan_freq > wlan_acs_ch_freq_arr[j]))
			break;
	}

	/* compute the pwr based on row and col of the table */
	return max_tx_pwr_arr[j * (ATH6KL_WWAN_LTE_COEX_MAX_CHN) + i];
}

static int ath6kl_lte_coex_send_wmi_cmd(struct ath6kl *ar)
{
#ifdef CONFIG_ATH6KL_WLAN_3WIRE_LTE_COEX
	struct sk_buff *skb;
	struct ath6kl *ar = ar->lte_coex->ar;
	struct wmi_set_lte_coex_state_cmd *fw_wmi_lte_data;

	skb  = (struct sk_buff *) ath6kl_wmi_get_buf(sizeof(struct
					wmi_set_lte_coex_state_cmd));

	if (!skb) {
		ath6kl_dbg(ATH6KL_DBG_LTE_COEX, "LTE_COEX: wmi cmd send fail");
		return -ENOMEM;
	}

	fw_wmi_lte_data = (struct wmi_set_lte_coex_state_cmd *) (skb->data);
	memcpy(fw_wmi_lte_data, &ar->lte_coex->wmi_lte_data,
			sizeof(struct wmi_set_lte_coex_state_cmd));
	ath6kl_dbg(ATH6KL_DBG_LTE_COEX,
	"LTE_COEX: SCM:%s ACM: %s WWM:%s WWS:%s TDD:%d ATP:%d STP:%d OFP:%d",
		GET_LTE_COEX_MODE(fw_wmi_lte_data->sta_lte_coex_mode),
		GET_LTE_COEX_MODE(fw_wmi_lte_data->ap_lte_coex_mode),
		GET_ATH6KL_LTE_COEX_WWAN_MODE(fw_wmi_lte_data->wwan_mode),
		GET_ATH6KL_LTE_COEX_WWAN_STATE(fw_wmi_lte_data->wwan_state),
		fw_wmi_lte_data->wwan_tdd_cfg, fw_wmi_lte_data->ap_max_tx_pwr,
		fw_wmi_lte_data->sta_max_tx_pwr,
		fw_wmi_lte_data->wwan_off_period);
	ath6kl_wmi_cmd_send(ar->wmi, 0, skb, WMI_SET_LTE_COEX_STATE_CMDID,
							NO_SYNC_WMIFLAG);
#endif
	return 0;
}

static void ath6kl_lte_coex_ap_reset(struct ath6kl *ar)
{
	struct ath6kl_vif *vif;

	spin_lock_bh(&ar->list_lock);
	list_for_each_entry(vif, &ar->vif_list, list) {
		if (vif->nw_type == AP_NETWORK) {
			ar->lte_coex->dev_ctx[vif->fw_vif_idx].acs_evt
						= ATH6KL_AP_ACS_RESET;
		}
	}
	spin_unlock_bh(&ar->list_lock);

}

static void ath6kl_setup_wlan_sta_lte_coex_mode(struct ath6kl *ar,
		int table_look_up_entries, struct _lte_coex_chk lte_coex_chk[],
		int send_wmi_cmd)
{
	int i, j, count = 0;
	struct ath6kl_vif *vif;
	uint32_t sta_freq = 0;

	if (ar->lte_coex->wwan_operational == 0)
		return ;

	ar->lte_coex->wmi_lte_data.sta_lte_coex_mode =
						LTE_COEX_MODE_DISABLED;

	spin_lock_bh(&ar->list_lock);
	list_for_each_entry(vif, &ar->vif_list, list) {
		if (vif->nw_type == INFRA_NETWORK) {
			sta_freq = ar->lte_coex->
				   dev_ctx[vif->fw_vif_idx].op_freq;
			break;
		}
	}
	spin_unlock_bh(&ar->list_lock);
	/* Select wwan band */
	for (i = 0; i < table_look_up_entries - 1; i++) {
		if (ar->lte_coex->wwan_freq >= lte_coex_chk[i].wwan_min_freq
		&& ar->lte_coex->wwan_freq < lte_coex_chk[i].wwan_max_freq) {
			if (ar->lte_coex->wwan_band == ATH6KL_WWAN_FDD &&
				(ar->lte_coex->wwan_bw != lte_coex_chk[i].wwan_bw))
				continue;
			/*select wlan band */
			count = lte_coex_chk[i].no_of_entry;
			for (j = i; j < i + count; j++) {
				if (sta_freq >= lte_coex_chk[j].wlan_min_freq
				&& sta_freq  <=
					lte_coex_chk[j].wlan_max_freq) {
					ar->lte_coex->wmi_lte_data.
					sta_lte_coex_mode
					= lte_coex_chk[j].sta_lte_coex_mode;
					ar->lte_coex->wwan_band &=
					lte_coex_chk[j].wwan_band;
					break;
				}
			}
			break;
		}
	}
	ar->lte_coex->wmi_lte_data.sta_max_tx_pwr =
		ath6kl_lte_coex_calc_txpwr(ar, sta_freq);
	if (send_wmi_cmd)
		ath6kl_lte_coex_send_wmi_cmd(ar);
}

static void ath6kl_lte_coex_check_acs(struct ath6kl_vif *vif,
		uint32_t ap_freq, uint8_t index,
		struct _lte_coex_chk lte_coex_chk[])
{
	struct ath6kl *ar = vif->ar;
	uint8_t j = 0, count = lte_coex_chk[index].no_of_entry;
	bool calc_tx_pwr = false;
	uint8_t vif_idx  = vif->fw_vif_idx;

	for (j = index; j < index + count; j++) {
		if (ap_freq >= lte_coex_chk[j].wlan_min_freq &&
			   ap_freq <= lte_coex_chk[j].wlan_max_freq) {
			/* AP up */
			ar->lte_coex->wmi_lte_data.ap_lte_coex_mode =
					lte_coex_chk[j].ap_lte_coex_mode;
			ar->lte_coex->acs_chan_mask =
				lte_coex_chk[j].acs_chan_mask;
			ar->lte_coex->wwan_band &= lte_coex_chk[j].wwan_band;
			if (!(ar->lte_coex->dev_ctx[vif_idx].acs_evt &
					(ATH6KL_AP_ACS_COMPLETED|
						ATH6KL_AP_ACS_NOT_NEEDED))) {
				if (lte_coex_chk[j].apply_acs) {
					ar->lte_coex->dev_ctx[vif_idx].acs_evt
						|= ATH6KL_AP_ACS_IN_PROGRESS;
					calc_tx_pwr = false;
					vif->acs_chan_mask =
						ar->lte_coex->acs_chan_mask;
					if (ar->acs_in_prog) {
						vif->ap_hold_conn = 1;
						mod_timer(
							&vif->ap_restart_timer,
							jiffies +
							msecs_to_jiffies(1 *
							AP_RESTART_TIMER_INVAL)
							);
					} else {
						ar->acs_in_prog = 1;
						ath6kl_wmi_ap_profile_commit(
							ar->wmi, vif_idx,
								&vif->profile);

						}
				} else {
					ar->lte_coex->dev_ctx[vif_idx].acs_evt
						|= ATH6KL_AP_ACS_NOT_NEEDED;
					calc_tx_pwr = true;
				}
			} else if (ar->lte_coex->dev_ctx[vif_idx].acs_evt &
					ATH6KL_AP_ACS_COMPLETED) {
					calc_tx_pwr = true;
			}
			ar->lte_coex->wmi_lte_data.ap_max_tx_pwr = -1;
			if (calc_tx_pwr)
				ar->lte_coex->wmi_lte_data.ap_max_tx_pwr =
					ath6kl_lte_coex_calc_txpwr(ar, ap_freq);
			break;
		}
	}
}


static void ath6kl_lte_coex_set_ap_mode(struct ath6kl *ar, uint8_t index,
		struct _lte_coex_chk lte_coex_chk[])
{
	struct ath6kl_vif *vif;
	uint32_t ap_freq;
	uint8_t vif_idx = 0;
	spin_lock_bh(&ar->list_lock);
	list_for_each_entry(vif, &ar->vif_list, list) {
		if (vif->nw_type != AP_NETWORK)
			continue;
		vif_idx = vif->fw_vif_idx;
		ap_freq = ar->lte_coex->dev_ctx[vif_idx].op_freq;
		/* select wlan band */
		if (!ap_freq) {
			/* AP not up, note down for future update */
			ar->lte_coex->acs_chan_mask =
				lte_coex_chk[index].acs_chan_mask;
			ar->lte_coex->wwan_band &=
				lte_coex_chk[index].wwan_band;
			ar->lte_coex->wmi_lte_data.ap_max_tx_pwr = -1;
			ar->lte_coex->dev_ctx[vif_idx].acs_evt =
							ATH6KL_AP_ACS_RESET;
		} else {
			ath6kl_lte_coex_check_acs(vif, ap_freq, index,
					lte_coex_chk);
			if (ar->lte_coex->dev_ctx[vif_idx].acs_evt
						& ATH6KL_AP_ACS_IN_PROGRESS)
				break;
		}
	}
	spin_unlock_bh(&ar->list_lock);
}

static void ath6kl_setup_wlan_ap_lte_coex_mode(struct ath6kl *ar,
		int send_wmi_cmd, int table_look_up_entries,
		struct _lte_coex_chk lte_coex_chk[])
{
	int i;

	if (ar->lte_coex->wwan_operational == 0)
		return ;

	ar->lte_coex->wmi_lte_data.ap_lte_coex_mode =
						LTE_COEX_MODE_DISABLED;
	ar->lte_coex->acs_chan_mask = AP_ACS_NONE;
	/* Select wwan band */
	for (i = 0; i < table_look_up_entries; i++) {
		if (ar->lte_coex->wwan_freq >= lte_coex_chk[i].wwan_min_freq &&
		ar->lte_coex->wwan_freq < lte_coex_chk[i].wwan_max_freq) {
			if (ar->lte_coex->wwan_band == ATH6KL_WWAN_FDD &&
				(ar->lte_coex->wwan_bw != lte_coex_chk[i].wwan_bw))
				continue;

			ath6kl_lte_coex_set_ap_mode(ar, i, lte_coex_chk);
			break;
		}
	}

	if (send_wmi_cmd)
		ath6kl_lte_coex_send_wmi_cmd(ar);
}

void ath6kl_lte_coex_update_wwan_data(struct ath6kl *ar, void *wmi_buf)
{
	int table_look_up_entries = 0;
	struct app_lte_coex_wwan_data_t *wwan =
				(struct app_lte_coex_wwan_data_t *)wmi_buf;

	ath6kl_info("LTE_COEX: QMI LTE band info:%d %d %d",
			wwan->band_info_valid, wwan->ul_freq, wwan->dl_freq);
	ath6kl_info("LTE_COEX: QMI TDD CFG:%d %d",
					wwan->tdd_info_valid, wwan->tdd_cfg);
	ath6kl_info("LTE_COEX: QMI off period:%d %d",
				wwan->off_period_valid, wwan->off_period);

	if (!(wwan->band_info_valid == 1 || wwan->tdd_info_valid == 1 ||
		wwan->off_period_valid == 1))
		return;

	ar->lte_coex->wwan_operational = 1;

	if (wwan->band_info_valid == 1) {
		ar->lte_coex->wwan_freq = wwan->ul_freq;
		ar->lte_coex->wwan_bw = wwan->ul_bw;

		if (wwan->ul_freq == 0) {
			if (wwan->dl_freq == 0) {
				ath6kl_dbg(ATH6KL_DBG_LTE_COEX,
				"LTE_COEX: LTE deactivated. Disable lte_coex");
				ar->lte_coex->wmi_lte_data.wwan_mode =
					LTE_COEX_WWAN_MODE_INVALID;
				ar->lte_coex->wmi_lte_data.wwan_state =
					LTE_COEX_WWAN_STATE_DEACTIVATED;
				ar->lte_coex->wwan_band = 0;
			} else {
				ath6kl_dbg(ATH6KL_DBG_LTE_COEX,
						"LTE_COEX: LTE Idle Rx");
				ar->lte_coex->wwan_freq = wwan->dl_freq;
				ar->lte_coex->wmi_lte_data.wwan_state =
						LTE_COEX_WWAN_STATE_IDLE;
				ar->lte_coex->wwan_band = ATH6KL_WWAN_BAND;
			}
		} else {
			ath6kl_dbg(ATH6KL_DBG_LTE_COEX, "LTE_COEX: LTE Active");
			if (wwan->ul_freq == wwan->dl_freq) {
				ar->lte_coex->wmi_lte_data.wwan_mode =
					LTE_COEX_WWAN_MODE_TDD_CONFIG;
				ar->lte_coex->wwan_band = ATH6KL_WWAN_TDD;
				table_look_up_entries = LTE_COEX_REF_TDD_ROWS;
			} else {
				ar->lte_coex->wmi_lte_data.wwan_mode =
					 LTE_COEX_WWAN_MODE_FDD_CONFIG;
				ar->lte_coex->wwan_band = ATH6KL_WWAN_FDD;
				table_look_up_entries = LTE_COEX_REF_FDD_ROWS;
			}
			ar->lte_coex->wmi_lte_data.wwan_state =
					LTE_COEX_WWAN_STATE_CONNECTED;
		}
	}

	if (wwan->tdd_info_valid == 1)
		ar->lte_coex->wmi_lte_data.wwan_tdd_cfg = wwan->tdd_cfg;

	if (wwan->off_period_valid == 1)
		ar->lte_coex->wmi_lte_data.wwan_off_period = wwan->off_period;

	if (ar->lte_coex->wmi_lte_data.wwan_state != LTE_COEX_WWAN_STATE_IDLE) {
		ath6kl_lte_coex_ap_reset(ar);
		ath6kl_setup_wlan_sta_lte_coex_mode(ar, table_look_up_entries,
				(ar->lte_coex->wwan_band & ATH6KL_WWAN_TDD) ?
				lte_coex_tdd_lookup_table :
				lte_coex_fdd_lookup_table, 0);
		/* send wmi cmd only once */
		ath6kl_setup_wlan_ap_lte_coex_mode(ar, SEND_WMI_CMD,
				table_look_up_entries,
				(ar->lte_coex->wwan_band & ATH6KL_WWAN_TDD) ?
				lte_coex_tdd_lookup_table :
				lte_coex_fdd_lookup_table);
		ath6kl_dbg(ATH6KL_DBG_LTE_COEX, "LTE_COEX: WWAN BAND: %s",
				GET_ATH6KL_WWAN_BAND(ar->lte_coex->wwan_band));
		ar->lte_coex->wmi_lte_data.wwan_off_period = 0;
	}
}

void ath6kl_lte_coex_update_wlan_data(struct ath6kl_vif *vif, uint32_t chan)
{
	struct ath6kl *ar = vif->ar;
	int table_look_up_entries = (ar->lte_coex->wwan_band & ATH6KL_WWAN_TDD) ?
					LTE_COEX_REF_TDD_ROWS :
					LTE_COEX_REF_FDD_ROWS;

	if (vif->nw_type == INFRA_NETWORK) {
		ar->lte_coex->dev_ctx[vif->fw_vif_idx].op_freq = chan;
		if (chan != 0)
			ath6kl_dbg(ATH6KL_DBG_LTE_COEX,
				"LTE_COEX: Station connected at %d Mhz", chan);
		else
			ath6kl_dbg(ATH6KL_DBG_LTE_COEX,
				"LTE_COEX: Station disconnected");

		ath6kl_setup_wlan_sta_lte_coex_mode(ar,
				table_look_up_entries,
				(ar->lte_coex->wwan_band & ATH6KL_WWAN_TDD) ?
				lte_coex_tdd_lookup_table :
				lte_coex_fdd_lookup_table, SEND_WMI_CMD);
	} else if (vif->nw_type == AP_NETWORK) {
		ar->lte_coex->dev_ctx[vif->fw_vif_idx].op_freq = chan;
		if (chan != 0) {
			ath6kl_dbg(ATH6KL_DBG_LTE_COEX,
				"LTE_COEX: AP Enabled at freq %d Mhz", chan);

			if (ar->lte_coex->dev_ctx[vif->fw_vif_idx].acs_evt
						& ATH6KL_AP_ACS_IN_PROGRESS) {
				ar->lte_coex->dev_ctx[vif->fw_vif_idx].acs_evt
						&= ~ATH6KL_AP_ACS_IN_PROGRESS;
				ar->lte_coex->dev_ctx[vif->fw_vif_idx].acs_evt
						|= ATH6KL_AP_ACS_COMPLETED;
			}
		} else
			ath6kl_dbg(ATH6KL_DBG_LTE_COEX,
					"LTE_COEX: AP Shutdown");
		ath6kl_setup_wlan_ap_lte_coex_mode(ar, SEND_WMI_CMD,
				table_look_up_entries,
				(ar->lte_coex->wwan_band & ATH6KL_WWAN_TDD) ?
				lte_coex_tdd_lookup_table :
				lte_coex_fdd_lookup_table);
	}

}

u32 ath6kl_get_ap_operating_chan_mask(uint32_t chan)
{
	u32 chan_mask = 0, bit = 0;

	bit = (chan - 2412) / 5;
	chan_mask = BIT(bit);

	if (!chan || chan_mask > 0x1fff)
		chan_mask = 0;

	return chan_mask;
}

bool ath6kl_check_lte_coex_acs(struct ath6kl *ar, uint16_t *ap_acs_ch,
		struct ath6kl_vif *cur_vif)
{
	struct ath6kl_vif *tmp_vif;
	bool ret = false;
	u32 ap_operating_chan_mask = 0;

	if (ar->lte_coex && ar->lte_coex->acs_chan_mask != AP_ACS_NONE) {
		list_for_each_entry(tmp_vif, &ar->vif_list, list) {
			if (tmp_vif->nw_type == AP_NETWORK) {
				if (test_bit(CONNECTED, &tmp_vif->flags)) {
					if (tmp_vif->fw_vif_idx != cur_vif->fw_vif_idx &&
						(tmp_vif->phy_mode != WMI_11A_MODE)) {
						ap_operating_chan_mask =
							ath6kl_get_ap_operating_chan_mask(tmp_vif->bss_ch);
						if (ar->lte_coex->acs_chan_mask &
							ap_operating_chan_mask)
							*ap_acs_ch =
								tmp_vif->bss_ch;
					}
				}
			}
		}

		if (!*ap_acs_ch) {
			*ap_acs_ch = cpu_to_le16(AP_ACS_USER_DEFINED);
			cur_vif->acs_chan_mask = ar->lte_coex->acs_chan_mask;
		}
		ret = true;
	}
	return ret;
}

int ath6kl_lte_coex_init(struct ath6kl *ar)
{
	ath6kl_dbg(ATH6KL_DBG_LTE_COEX, "LTE_COEX: WWAN Coex Module Init");
	ar->lte_coex = (struct ath6kl_lte_coex_priv *)
		kzalloc(sizeof(struct ath6kl_lte_coex_priv), GFP_KERNEL);
	if (!ar->lte_coex)
		return -ENOMEM;

	ar->lte_coex->ar = ar;
	ar->lte_coex->acs_chan_mask = AP_ACS_NONE;

	return 0;
}

void ath6kl_lte_coex_deinit(struct ath6kl *ar)
{
	ath6kl_dbg(ATH6KL_DBG_LTE_COEX, "LTE_COEX: WWAN Coex Module Deinit");
	kfree(ar->lte_coex);
	ar->lte_coex = NULL;
}


void ath6kl_tm_rx_wmi_event(struct ath6kl *ar, void *buf, size_t buf_len)
{
	struct sk_buff *skb;


	if (!buf || buf_len == 0)
		return;

	skb = cfg80211_testmode_alloc_event_skb(ar->wiphy, buf_len, GFP_KERNEL);
	if (!skb) {
		ath6kl_warn("failed to allocate testmode rx skb!\n");
		return;
	}
	NLA_PUT_U32(skb, ATH6KL_TM_ATTR_CMD, ATH6KL_TM_CMD_WMI_CMD);
	NLA_PUT(skb, ATH6KL_TM_ATTR_DATA, buf_len, buf);
	cfg80211_testmode_event(skb, GFP_KERNEL);
	return;

nla_put_failure:
	kfree_skb(skb);
	ath6kl_warn("nla_put failed on testmode rx skb!\n");
}


void ath6kl_wmicfg_send_stats(struct ath6kl_vif *vif,
			      struct target_stats *stats)
{
	u32 *buff = kzalloc(sizeof(*stats) + 4, GFP_KERNEL);
	if (buff == NULL)
		return;

	buff[0] = WMI_REPORT_STATISTICS_EVENTID;
	memcpy(buff+1, stats, sizeof(struct target_stats));
	ath6kl_tm_rx_wmi_event(vif->ar->wmi->parent_dev, buff,
			       sizeof(struct target_stats)+4);
	kfree(buff);
}
