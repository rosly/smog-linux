/*
 * sun8i-ce-cipher.c - hardware cryptographic accelerator for
 * Allwinner H3/A64 SoC
 *
 * Copyright (C) 2016-2017 Corentin LABBE <clabbe.montjoie@gmail.com>
 *
 * This file add support for AES cipher with 128,192,256 bits keysize in
 * CBC and ECB mode.
 *
 * You could find a link for the datasheet in Documentation/arm/sunxi/README
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <linux/clk.h>
#include <linux/irq.h>
#include <linux/crypto.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <crypto/scatterwalk.h>
#include <linux/scatterlist.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/reset.h>
#include <crypto/sha.h>
#include <crypto/internal/akcipher.h>
#include <crypto/internal/rsa.h>
#include <linux/dma-mapping.h>
#include "sun8i-ss.h"

int sun8i_rsa_init(struct crypto_akcipher *tfm)
{
	struct sun8i_tfm_rsa_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct akcipher_alg *alg = crypto_akcipher_alg(tfm);
	struct sun8i_ss_alg_template *algt;

	algt = container_of(alg, struct sun8i_ss_alg_template, alg.rsa);
	ctx->ss = algt->ss;

	dev_info(ctx->ss->dev, "%s\n", __func__);

	ctx->fallback = crypto_alloc_akcipher("rsa", 0, CRYPTO_ALG_NEED_FALLBACK);
	if (IS_ERR(ctx->fallback)) {
		dev_err(ctx->ss->dev, "ERROR: Cannot allocate fallback\n");
		return PTR_ERR(ctx->fallback);
	}
	/*dev_info(ctx->ss->dev, "Use %s as fallback\n", ctx->fallback->base.cra_driver_name);*/

	return 0;
}

void sun8i_rsa_exit(struct crypto_akcipher *tfm)
{
	struct sun8i_tfm_rsa_ctx *ctx = akcipher_tfm_ctx(tfm);

	dev_info(ctx->ss->dev, "%s\n", __func__);
	crypto_free_akcipher(ctx->fallback);
}

static inline u8 *caam_read_raw_data(const u8 *buf, size_t *nbytes)
{
	u8 *val;

	while (!*buf && *nbytes) {
		buf++;
		(*nbytes)--;
	}

	val = kzalloc(*nbytes, GFP_DMA | GFP_KERNEL);
	if (!val)
		return NULL;

	memcpy(val, buf, *nbytes);
	return val;
}

/* IV is pubmodulus
 *
 * mode MUL(2) IV size
 * mode EXP(0) key size (so key is modulus ?)
 */
int sun8i_rsa_encrypt(struct akcipher_request *req)
{
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	struct sun8i_tfm_rsa_ctx *ctx = akcipher_tfm_ctx(tfm);
	int flow = 0;
	struct ss_task *cet;
	struct sun8i_ss_ctx *ss = ctx->ss;
	int err = 0;
	u8 *modulus;
	int nr_sgs, nr_sgd;
	u32 v;
	int i;
	unsigned int todo, len;
	struct scatterlist *sg;
	void *sgb, *exp, *tmp;
	u8 *p;
	u8 *s, *t;
	u8 u;

	dev_info(ctx->ss->dev, "%s modulus %zu e=%zu d=%zu c=%zu slen=%u dlen=%u\n", __func__,
		ctx->rsa_key.n_sz, ctx->rsa_key.e_sz, ctx->rsa_key.d_sz,
		ctx->rsa_key.n_sz,
		req->src_len, req->dst_len);

	cet = ctx->ss->tl[flow];
	memset(cet, 0, sizeof(struct ss_task));

	cet->t_id = flow;
	cet->t_common_ctl = 32 | BIT(31);
#define RSA_LENDIV 4
	cet->t_dlen = req->src_len / RSA_LENDIV;

	modulus = caam_read_raw_data(ctx->rsa_key.n, &ctx->rsa_key.n_sz);
	if (!modulus) {
		dev_err(ss->dev, "Cannot get modulus\n");
		err = -EFAULT;
		goto theend;
	}

	dev_info(ss->dev, "Final modulus size %u\n", ctx->rsa_key.n_sz);

	exp = kzalloc(ctx->rsa_key.n_sz, GFP_KERNEL | GFP_DMA);
	if (!exp)
		return -ENOMEM;
	/*memset(exp, 0xFF, ctx->rsa_key.n_sz);*/
	memcpy(exp, ctx->rsa_key.e, ctx->rsa_key.e_sz);
	p = exp;
	/*p[0] = 0x01;*/
	/*p[3] = 3;*/
	/*p[3] = 0x11;*/
	print_hex_dump(KERN_INFO, "EXP ", DUMP_PREFIX_NONE, 16, 1, exp, ctx->rsa_key.n_sz, false);

	/*cet->t_key = dma_map_single(ss->dev, ctx->rsa_key.e, ctx->rsa_key.e_sz, DMA_TO_DEVICE);*/
	/*cet->t_key = dma_map_single(ss->dev, modulus, ctx->rsa_key.n_sz, DMA_TO_DEVICE);*/
	cet->t_key = dma_map_single(ss->dev, exp, ctx->rsa_key.n_sz, DMA_TO_DEVICE);
	if (dma_mapping_error(ss->dev, cet->t_key)) {
		dev_err(ss->dev, "Cannot DMA MAP KEY\n");
		err = -EFAULT;
		goto theend;
	}

	tmp = kzalloc(ctx->rsa_key.n_sz, GFP_KERNEL | GFP_DMA);
	memcpy(tmp, modulus, ctx->rsa_key.n_sz);
	s = modulus;
	t = tmp;
	for (i = 0; i < ctx->rsa_key.n_sz; i++)
		s[i] = t[ctx->rsa_key.n_sz - i - 1];
	i = 0;
	while (i < ctx->rsa_key.n_sz) {
		u = s[i];
		s[i] = s[i + 3];
		s[i + 3] = u;
		u = s[i + 1];
		s[i + 1] = s[i + 2];
		s[i + 2] = u;
		i += 4;
	}

	cet->t_iv = dma_map_single(ss->dev, modulus, ctx->rsa_key.n_sz, DMA_TO_DEVICE);
	/*cet->t_iv = dma_map_single(ss->dev, exp, ctx->rsa_key.n_sz, DMA_TO_DEVICE);*/
	/*cet->t_iv = dma_map_single(ss->dev, ctx->rsa_key.e, ctx->rsa_key.e_sz, DMA_TO_DEVICE);*/
	if (dma_mapping_error(ss->dev, cet->t_iv)) {
		dev_err(ss->dev, "Cannot DMA MAP IV\n");
		err = -EFAULT;
		goto theend;
	}

	print_hex_dump(KERN_INFO, "KEY ", DUMP_PREFIX_NONE, 16, 1,  ctx->rsa_key.e, ctx->rsa_key.e_sz, false);

	print_hex_dump(KERN_INFO, "MOD ", DUMP_PREFIX_NONE, 16, 1, modulus, ctx->rsa_key.n_sz, false);

/*
	nr_sgs = dma_map_sg(ss->dev, req->src, sg_nents(req->src), DMA_TO_DEVICE);
	if (nr_sgs < 0) {
		dev_err(ss->dev, "Cannot DMA MAP src\n");
		err = -EFAULT;
		goto theend;
	}
*/
	sgb = kzalloc(ctx->rsa_key.n_sz, GFP_KERNEL | GFP_DMA);
	if (!sgb)
		return -ENOMEM;
	memset(sgb, 0xFF, ctx->rsa_key.n_sz);
	err = sg_copy_to_buffer(req->src, sg_nents(req->src), sgb, req->src_len);
/*
	tmp = kzalloc(ctx->rsa_key.n_sz, GFP_KERNEL | GFP_DMA);
	memcpy(tmp, sgb, ctx->rsa_key.n_sz);
	s = sgb;
	t = tmp;
	for (i = 0; i < ctx->rsa_key.n_sz; i++)
		s[i] = t[ctx->rsa_key.n_sz - i - 1];
*/
	print_hex_dump(KERN_INFO, "SRC ", DUMP_PREFIX_NONE, 16, 1, sgb, ctx->rsa_key.n_sz, false);

	cet->t_src[0].addr = dma_map_single(ss->dev, sgb, ctx->rsa_key.n_sz, DMA_TO_DEVICE);
	if (dma_mapping_error(ss->dev, cet->t_src[0].addr)) {
		dev_err(ss->dev, "Cannot DMA MAP SRC\n");
		err = -EFAULT;
		goto theend;
	}

	nr_sgd = dma_map_sg(ss->dev, req->dst, sg_nents(req->dst), DMA_FROM_DEVICE);
	if (nr_sgd < 0) {
		dev_err(ss->dev, "Cannot DMA MAP dst\n");
		err = -EFAULT;
		goto theend;
	}
/*
	len = req->src_len;
	for_each_sg(req->src, sg, nr_sgs, i) {
		cet->t_src[i].addr = sg_dma_address(sg);
		todo = min(len, sg_dma_len(sg));
		cet->t_src[i].len = todo / RSA_LENDIV;
		dev_info(ss->dev, "SRC %d %u\n", i, todo);
		len -= todo;
	}*/

	req->dst_len = req->src_len;
	req->dst_len = ctx->rsa_key.n_sz;
	len = req->dst_len;
	for_each_sg(req->dst, sg, nr_sgd, i) {
		cet->t_dst[i].addr = sg_dma_address(sg);
		todo = min(len, sg_dma_len(sg));
		cet->t_dst[i].len = todo / RSA_LENDIV;
		dev_info(ss->dev, "DST %d %u\n", i, todo);
		len -= todo;
	}

	/* HACKS */
	/*cet->t_asym_ctl |= 2 << 16;*/
	switch (ctx->rsa_key.n_sz * 8) {
	case 512:
		dev_info(ss->dev, "RSA 512\n");
		break;
	case 1024:
		dev_info(ss->dev, "RSA 1024\n");
		cet->t_asym_ctl |= 1 << 28;
		break;
	case 2048:
		dev_info(ss->dev, "RSA 2048\n");
		cet->t_asym_ctl |= 2 << 28;
		break;
	case 4096:
		cet->t_asym_ctl |= 3 << 28;
		break;
	default:
		dev_info(ss->dev, "RSA invalid\n");
	}
	cet->t_src[0].len = ctx->rsa_key.n_sz / RSA_LENDIV;
	/*cet->t_dst[0].len = ctx->rsa_key.n_sz / RSA_LENDIV;*/
	cet->t_dlen = ctx->rsa_key.n_sz / RSA_LENDIV;

	dev_info(ss->dev, "SRC %u\n", cet->t_src[0].len);
	dev_info(ss->dev, "DST %u\n", cet->t_dst[0].len);

	dev_info(ss->dev, "CTL %x %x %x\n", cet->t_common_ctl, cet->t_sym_ctl, cet->t_asym_ctl);

	err = sun8i_ce_run_task(ss, flow, "RSA");
/*
	v = readl(ss->base + CE_ICR);
	v |= 1 << flow;
	writel(v, ss->base + CE_ICR);

	reinit_completion(&ss->chanlist[flow].complete);
	writel(ss->ce_t_phy[flow], ss->base + CE_TDQ);

	ss->chanlist[flow].status = 0;
	wmb();

	writel(1, ss->base + CE_TLR);

	wait_for_completion_interruptible_timeout(&ss->chanlist[flow].complete,
						  msecs_to_jiffies(5000));

	if (ss->chanlist[flow].status == 0) {
		dev_err(ss->dev, "DMA timeout\n");
		err = -EINVAL;
	}

	v = readl(ss->base + CE_ESR);
	if (v)
		dev_info(ss->dev, "CE ERROR %x\n", v);
	else
		err = 0;
*/
	/*dma_unmap_sg(ss->dev, req->src, nr_sgs, DMA_TO_DEVICE);*/
	dma_unmap_single(ss->dev, cet->t_src[0].addr, ctx->rsa_key.n_sz, DMA_TO_DEVICE);
	dma_unmap_sg(ss->dev, req->dst, nr_sgd, DMA_FROM_DEVICE);
	dma_unmap_single(ss->dev, cet->t_key, ctx->rsa_key.n_sz, DMA_TO_DEVICE);
	dma_unmap_single(ss->dev, cet->t_iv, ctx->rsa_key.n_sz, DMA_TO_DEVICE);

	/*sg_copy_to_buffer(req->dst, sg_nents(req->dst), modulus, req->dst_len);*/
	/*print_hex_dump(KERN_INFO, "DST ", DUMP_PREFIX_NONE, 16, 1,  modulus, ctx->rsa_key.n_sz, false);*/

	kfree(modulus);
theend:
	return err;
}

int sun8i_rsa_decrypt(struct akcipher_request *req)
{
	pr_info("%s\n", __func__);
	return 0;
}

int sun8i_rsa_sign(struct akcipher_request *req)
{
	pr_info("%s\n", __func__);
	return 0;
}

int sun8i_rsa_verify(struct akcipher_request *req)
{
	pr_info("%s\n", __func__);
	return 0;
}

int sun8i_rsa_set_priv_key(struct crypto_akcipher *tfm, const void *key, unsigned int keylen)
{
	struct sun8i_tfm_rsa_ctx *ctx = akcipher_tfm_ctx(tfm);
	int ret;

	pr_info("%s keylen=%u\n", __func__, keylen);

	ret = rsa_parse_priv_key(&ctx->rsa_key, key, keylen);
	if (ret) {
		dev_err(ctx->ss->dev, "Invalid key\n");
		return ret;
	}

	return 0;
}

int sun8i_rsa_set_pub_key(struct crypto_akcipher *tfm, const void *key, unsigned int keylen)
{
	pr_info("%s\n", __func__);
	return 0;
}

int sun8i_rsa_max_size(struct crypto_akcipher *tfm)
{
	pr_info("%s\n", __func__);

	return 4096 / 8;
}

