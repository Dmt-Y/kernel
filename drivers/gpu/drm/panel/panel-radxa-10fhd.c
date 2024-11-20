// SPDX-License-Identifier: GPL-2.0

#include <linux/backlight.h>
#include <linux/delay.h>
#include <linux/gpio/consumer.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/regulator/consumer.h>

#include <drm/drm_mipi_dsi.h>
#include <drm/drm_modes.h>
#include <drm/drm_panel.h>
#include <drm/drm_probe_helper.h>

#include <video/mipi_display.h>

static const char * const regulator_names[] = {
	"vdd",		/* 3v3 */
	"vccio",	/* 1v8 */
};

struct radxa_10fhd {
	enum drm_panel_orientation orientation;
	struct drm_panel panel;
	struct gpio_desc *reset_gpio;
	struct mipi_dsi_device *dsi;
	struct regulator_bulk_data supplies[ARRAY_SIZE(regulator_names)];
};

static inline struct radxa_10fhd *to_radxa_10fhd(struct drm_panel *panel)
{
	return container_of(panel, struct radxa_10fhd, panel);
}

static int radxa_10fhd_prepare(struct drm_panel *panel)
{
	struct radxa_10fhd *ctx = to_radxa_10fhd(panel);
	struct mipi_dsi_device *dsi = ctx->dsi;
	int ret;

	ret = regulator_bulk_enable(ARRAY_SIZE(ctx->supplies), ctx->supplies);
	if (ret < 0) {
		dev_err(&dsi->dev, "Regulator bulk enable failed: %d\n", ret);
		return ret;
	}

	gpiod_set_value_cansleep(ctx->reset_gpio, 0);
	msleep(120);
	gpiod_set_value_cansleep(ctx->reset_gpio, 1);
	msleep(120);
	gpiod_set_value_cansleep(ctx->reset_gpio, 0);
	msleep(120);

	return 0;
}

static int radxa_10fhd_unprepare(struct drm_panel *panel)
{
	struct radxa_10fhd *ctx = to_radxa_10fhd(panel);
	struct mipi_dsi_device *dsi = ctx->dsi;
	int ret;

	gpiod_set_value_cansleep(ctx->reset_gpio, 1);

	ret = regulator_bulk_disable(ARRAY_SIZE(ctx->supplies), ctx->supplies);
	if (ret)
		dev_err(&dsi->dev, "Regulator bulk disable failed: %d\n", ret);

	return 0;
}

static int radxa_10fhd_enable(struct drm_panel *panel)
{
	struct radxa_10fhd *ctx = to_radxa_10fhd(panel);
	struct mipi_dsi_multi_context dsi_ctx = { .dsi = ctx->dsi };

	mipi_dsi_dcs_exit_sleep_mode_multi(&dsi_ctx);
	mipi_dsi_msleep(&dsi_ctx, 120);
	mipi_dsi_dcs_set_display_on_multi(&dsi_ctx);
	mipi_dsi_msleep(&dsi_ctx, 120);

	return dsi_ctx.accum_err;
}

static int radxa_10fhd_disable(struct drm_panel *panel)
{
	struct radxa_10fhd *ctx = to_radxa_10fhd(panel);
	struct mipi_dsi_multi_context dsi_ctx = { .dsi = ctx->dsi };

	mipi_dsi_dcs_set_display_off_multi(&dsi_ctx);
	mipi_dsi_dcs_enter_sleep_mode_multi(&dsi_ctx);
	mipi_dsi_msleep(&dsi_ctx, 120);

	return dsi_ctx.accum_err;
}

static const struct drm_display_mode radxa_10fhd_mode = {
	.clock 		= 160000,

	.hdisplay	= 1200,
	.hsync_start	= 1200 + 80,
	.hsync_end	= 1200 + 80 + 8,
	.htotal		= 1200 + 80 + 8 + 60,
	.vdisplay	= 1920,
	.vsync_start	= 1920 + 35,
	.vsync_end	= 1920 + 35 + 4,
	.vtotal		= 1920 + 35 + 4 + 25,

	.width_mm	= 135,
	.height_mm	= 216,
};

static int radxa_10fhd_get_modes(struct drm_panel *panel,
				 struct drm_connector *connector)
{
	return drm_connector_helper_get_modes_fixed(connector, &radxa_10fhd_mode);
}

static enum drm_panel_orientation radxa_10fhd_get_orientation(struct drm_panel *panel)
{
	struct radxa_10fhd *ctx = to_radxa_10fhd(panel);

	return ctx->orientation;
}

static const struct drm_panel_funcs radxa_10fhd_funcs = {
	.prepare = radxa_10fhd_prepare,
	.unprepare = radxa_10fhd_unprepare,
	.enable = radxa_10fhd_enable,
	.disable = radxa_10fhd_disable,
	.get_modes = radxa_10fhd_get_modes,
	.get_orientation = radxa_10fhd_get_orientation,
};

static int radxa_10fhd_probe(struct mipi_dsi_device *dsi)
{
	struct device *dev = &dsi->dev;
	struct radxa_10fhd *ctx;
	int i, ret;


	ctx = devm_drm_panel_alloc(dev, struct radxa_10fhd, panel,
				   &radxa_10fhd_funcs,
				   DRM_MODE_CONNECTOR_DSI);

	if (IS_ERR(ctx))
		return PTR_ERR(ctx);

	for (i = 0; i < ARRAY_SIZE(ctx->supplies); i++)
		ctx->supplies[i].supply = regulator_names[i];

	ret = devm_regulator_bulk_get(dev, ARRAY_SIZE(ctx->supplies), ctx->supplies);
	if (ret)
		return dev_err_probe(dev, ret, "Failed to get regulators\n");

	ctx->reset_gpio = devm_gpiod_get(dev, "reset", GPIOD_OUT_LOW);
	if (IS_ERR(ctx->reset_gpio))
		return dev_err_probe(dev, PTR_ERR(ctx->reset_gpio), "Failed to get reset gpio\n");

	ctx->dsi = dsi;
	mipi_dsi_set_drvdata(dsi, ctx);

	dsi->lanes = 4;
	dsi->format = MIPI_DSI_FMT_RGB888;
	dsi->mode_flags = MIPI_DSI_MODE_VIDEO | MIPI_DSI_MODE_VIDEO_BURST |
			  MIPI_DSI_MODE_LPM | MIPI_DSI_MODE_NO_EOT_PACKET;

	ret = drm_panel_of_backlight(&ctx->panel);
	if (ret)
		return dev_err_probe(dev, ret, "Failed to get backlight\n");

	ret = of_drm_get_panel_orientation(dev->of_node, &ctx->orientation);
	if (ret)
		return dev_err_probe(dev, ret, "Failed to get orientation\n");

	drm_panel_add(&ctx->panel);

	ret = mipi_dsi_attach(dsi);
	if (ret < 0) {
		dev_err(dev, "Failed to attach to DSI host: %d\n", ret);
		drm_panel_remove(&ctx->panel);
	}

	return ret;
}

static void radxa_10fhd_remove(struct mipi_dsi_device *dsi)
{
	struct radxa_10fhd *ctx = mipi_dsi_get_drvdata(dsi);
	int ret;

	ret = mipi_dsi_detach(dsi);
	if (ret < 0)
		dev_err(&dsi->dev, "Failed to detach from DSI host: %d\n", ret);

	drm_panel_remove(&ctx->panel);
}

static const struct of_device_id radxa_10fhd_of_match[] = {
	{.compatible = "radxa,display-10fhd"},
	{ /*sentinel*/ }
};
MODULE_DEVICE_TABLE(of, radxa_10fhd_of_match);

static struct mipi_dsi_driver radxa_10fhd_driver = {
	.probe = radxa_10fhd_probe,
	.remove = radxa_10fhd_remove,
	.driver = {
		.name = "panel-radxa-10fhd",
		.of_match_table = radxa_10fhd_of_match,
	},
};

module_mipi_dsi_driver(radxa_10fhd_driver);

MODULE_AUTHOR("Dmitry Yashin <dmt.yashin@gmail.com>");
MODULE_DESCRIPTION("Radxa 10FHD MIPI DSI panel driver");
MODULE_LICENSE("GPL v2");
