
#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>


#include "l2tpd_logging.h"

/* default categories */
static struct log_info_cat l2tpd_categories[] = {
	[DL2TP] = {
		.name = "DL2TP",
		.description = "L2TP logging messages",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

static const struct log_info l2tpd_log_info = {
	.cat = l2tpd_categories,
	.num_cat = ARRAY_SIZE(l2tpd_categories),
};

void l2tpd_log_init()
{
	osmo_init_logging(&l2tpd_log_info);
}
