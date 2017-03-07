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

#include <linux/crypto.h>
#include <linux/io.h>
#include <crypto/scatterwalk.h>
#include <linux/scatterlist.h>
#include <linux/dma-mapping.h>
#include <crypto/internal/skcipher.h>
#include "sun8i-ss.h"

int sun8i_ss_cipher(struct ablkcipher_request *areq)
{
	struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(areq);
	struct sun8i_tfm_ctx *op = crypto_ablkcipher_ctx(tfm);
	struct sun8i_ss_ctx *ss = op->ss;
	struct sun8i_cipher_req_ctx *rctx = ablkcipher_request_ctx(areq);
	int flow = ss->flow;
	struct ss_task *cet;
	int nr_sgs, nr_sgd;
	struct scatterlist *sg;
	struct scatterlist *in_sg = areq->src;
	struct scatterlist *out_sg = areq->dst;
	int i;
	int ret;
	int no_chunk, chunked_src, chunked_dst;
	int err = 0;
	unsigned int todo, len;
	struct crypto_alg *alg = tfm->base.__crt_alg;
	/*struct crypto_alg *alg = &(crypto_ablkcipher_tfm(tfm))->__crt_alg;*/
	struct sun8i_ss_alg_template *algt;

	algt = container_of(alg, struct sun8i_ss_alg_template, alg.crypto);

	/*dev_info(ss->dev, "%s %u %x\n", __func__, areq->nbytes, rctx->common);*/

	chunked_src = 1;
	sg = areq->src;
	while (sg && chunked_src == 1) {
		if ((sg->length % 4) != 0)
			chunked_src = 0;
		if (!IS_ALIGNED(sg->offset, sizeof(u32))) {
			/*dev_info(ss->dev, "Align problem on src\n");*/
			chunked_src = 0;
		}
		sg = sg_next(sg);
	}
	chunked_dst = 1;
	sg = areq->dst;
	while (sg && chunked_dst == 1) {
		if ((sg->length % 4) != 0)
			chunked_dst = 0;
		if (!IS_ALIGNED(sg->offset, sizeof(u32))) {
			/*dev_info(ss->dev, "Align problem on dst\n");*/
			chunked_dst = 0;
		}
		sg = sg_next(sg);
	}

	/* on SS, src and dst SG must have the same len */

	if (chunked_src == 0 || chunked_dst == 0 || sg_nents(in_sg) > 8) {
		struct blkcipher_desc fallback_desc = {
			.tfm	= op->fallback_tfm,
			.info	= areq->info,
			.flags	= 0,
		};
		if (rctx->op_dir & SS_DECRYPTION)
			return crypto_blkcipher_decrypt_iv(&fallback_desc,
				areq->dst, areq->src, areq->nbytes);
		else
			return crypto_blkcipher_encrypt_iv(&fallback_desc,
				areq->dst, areq->src, areq->nbytes);
	}

	flow = rctx->flow;

	mutex_lock(&ss->chanlock[flow]);

	cet = ss->tl[flow];
	memset(cet, 0, sizeof(struct ss_task));

	cet->t_id = flow;
	cet->t_common_ctl = ss->variant->alg_cipher[algt->ce_algo_id];
	cet->t_common_ctl = rctx->op_dir | BIT(31);
	cet->t_dlen = areq->nbytes / 4;

	cet->t_sym_ctl = ss->variant->op_mode[algt->ce_blockmode];
	cet->t_sym_ctl |= op->keymode;

	ss->chanlist[flow].op_mode = ss->variant->op_mode[algt->ce_blockmode];
	ss->chanlist[flow].op_dir = rctx->op_dir;
	ss->chanlist[flow].method = ss->variant->alg_cipher[algt->ce_algo_id];
	ss->chanlist[flow].keylen = op->keylen;

/*
	for (i = 0; i < 8; i++) {
		cet->t_src[i].len = 0;
		cet->t_dst[i].len = 0;
	}
	cet->next = 0;
*/
	cet->t_key = dma_map_single(ss->dev, op->key, op->keylen,
				    DMA_TO_DEVICE);
	if (dma_mapping_error(ss->dev, cet->t_key)) {
		dev_err(ss->dev, "Cannot DMA MAP KEY\n");
		err = -EFAULT;
		goto theend;
	}

	if (areq->info) {
		ss->chanlist[flow].ivlen = crypto_ablkcipher_ivsize(tfm);
		ss->chanlist[flow].bounce_iv = kzalloc(ss->chanlist[flow].ivlen,
						       GFP_KERNEL | GFP_DMA);
		if (!ss->chanlist[flow].bounce_iv) {
			err = -ENOMEM;
			goto theend;
		}
		memcpy(ss->chanlist[flow].bounce_iv, areq->info,
		       crypto_ablkcipher_ivsize(tfm));
		ss->chanlist[flow].next_iv = kzalloc(ss->chanlist[flow].ivlen,
						     GFP_KERNEL | GFP_DMA);
		if (!ss->chanlist[flow].next_iv) {
			err = -ENOMEM;
			goto theend;
		}
	}

	/* check for chunked SGs */
	no_chunk = 1;
	sg = areq->src;
	while (sg && no_chunk == 1) {
		if ((sg->length % 4) != 0)
			no_chunk = 0;
		if (!IS_ALIGNED(sg->offset, sizeof(u32))) {
			dev_info(ss->dev, "Align problem on src\n");
			no_chunk = 0;
		}
		sg = sg_next(sg);
	}
	if (no_chunk == 0 || sg_nents(in_sg) > 8) {
		dev_info(ss->dev, "Bounce src\n");
		ret = sun8i_ss_bounce_src(areq, flow);
		if (ret) {
			dev_err(ss->dev, "Cannot bounce src\n");
			err = -EFAULT;
			goto theend;
		}
		in_sg = ss->chanlist[flow].bounce_src;
	}
	no_chunk = 1;
	sg = areq->dst;
	while (sg && no_chunk == 1) {
		if ((sg->length % 4) != 0)
			no_chunk = 0;
		if (!IS_ALIGNED(sg->offset, sizeof(u32))) {
			dev_info(ss->dev, "Align problem on dst\n");
			no_chunk = 0;
		}
		sg = sg_next(sg);
	}
	if (no_chunk == 0) {
		dev_info(ss->dev, "Bounce dst\n");
		ret = sun8i_ss_bounce_dst(areq, flow);
		if (ret) {
			dev_err(ss->dev, "Cannot bounce dst\n");
			err = -EFAULT;
			goto theend;
		}
		out_sg = ss->chanlist[flow].bounce_dst;
	}

	if (in_sg == out_sg) {
		nr_sgs = dma_map_sg(ss->dev, in_sg, sg_nents(in_sg),
				    DMA_BIDIRECTIONAL);
		if (nr_sgs < 0 || nr_sgs > 8) {
			dev_info(ss->dev, "Invalid sg number %d\n", nr_sgs);
			err = -EINVAL;
			goto theend;
		}
		nr_sgd = nr_sgs;
	} else {
		nr_sgs = dma_map_sg(ss->dev, in_sg, sg_nents(in_sg),
				    DMA_TO_DEVICE);
		if (nr_sgs < 0 || nr_sgs > 8) {
			dev_info(ss->dev, "Invalid sg number %d\n", nr_sgs);
			err = -EINVAL;
			goto theend;
		}
		nr_sgd = dma_map_sg(ss->dev, out_sg, sg_nents(out_sg),
				    DMA_FROM_DEVICE);
		if (nr_sgd < 0 || nr_sgd > 8) {
			dev_info(ss->dev, "Invalid sg number %d\n", nr_sgd);
			err = -EINVAL;
			goto theend;
		}
	}

	len = areq->nbytes;
	for_each_sg(in_sg, sg, nr_sgs, i) {
		cet->t_src[i].addr = sg_dma_address(sg);
		todo = min(len, sg_dma_len(sg));
		cet->t_src[i].len = todo / 4;
		len -= todo;
	}

	len = areq->nbytes;
	for_each_sg(out_sg, sg, nr_sgd, i) {
		cet->t_dst[i].addr = sg_dma_address(sg);
		todo = min(len, sg_dma_len(sg));
		cet->t_dst[i].len = todo / 4;
		len -= todo;
	}

	err = sun8i_ce_run_task(ss, flow, "cipher");

	if (areq->info) {
		memcpy(areq->info, ss->chanlist[flow].next_iv,
		       ss->chanlist[flow].ivlen);
		kzfree(ss->chanlist[flow].bounce_iv);
		kzfree(ss->chanlist[flow].next_iv);
		ss->chanlist[flow].bounce_iv = NULL;
		ss->chanlist[flow].next_iv = NULL;
	}

	dma_unmap_single(ss->dev, cet->t_key, op->keylen, DMA_TO_DEVICE);
	if (in_sg == out_sg) {
		dma_unmap_sg(ss->dev, in_sg, nr_sgs, DMA_BIDIRECTIONAL);
	} else {
		dma_unmap_sg(ss->dev, in_sg, nr_sgs, DMA_TO_DEVICE);
		dma_unmap_sg(ss->dev, out_sg, nr_sgd, DMA_FROM_DEVICE);
	}

	if (areq->dst != out_sg) {
		dev_info(ss->dev, "Copy back\n");
		sg_copy_from_buffer(areq->dst, sg_nents(areq->dst),
				    ss->chanlist[flow].bufdst, areq->nbytes);
		kfree(ss->chanlist[flow].bufsrc);
		kfree(ss->chanlist[flow].bufdst);
		ss->chanlist[flow].bufsrc = NULL;
		ss->chanlist[flow].bufdst = NULL;
		kfree(ss->chanlist[flow].bounce_src);
		kfree(ss->chanlist[flow].bounce_dst);
		ss->chanlist[flow].bounce_src = NULL;
		ss->chanlist[flow].bounce_dst = NULL;
	}
theend:
	mutex_unlock(&ss->chanlock[flow]);

	return err;
}

int sun8i_ss_cbc_aes_decrypt(struct ablkcipher_request *areq)
{
	struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(areq);
	struct sun8i_tfm_ctx *op = crypto_ablkcipher_ctx(tfm);
	struct sun8i_cipher_req_ctx *rctx = ablkcipher_request_ctx(areq);
	int e = get_engine_number(op->ss);

	rctx->op_dir = SS_DECRYPTION;
	rctx->flow = e;

	return crypto_transfer_cipher_request_to_engine(op->ss->engines[e],
							areq);
}

int sun8i_ss_cbc_aes_encrypt(struct ablkcipher_request *areq)
{
	struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(areq);
	struct sun8i_tfm_ctx *op = crypto_ablkcipher_ctx(tfm);
	struct sun8i_cipher_req_ctx *rctx = ablkcipher_request_ctx(areq);
	int e = get_engine_number(op->ss);

	rctx->op_dir = SS_ENCRYPTION;
	rctx->flow = e;

	return crypto_transfer_cipher_request_to_engine(op->ss->engines[e],
							areq);
}

int sun8i_ss_cipher_init(struct crypto_tfm *tfm)
{
	struct sun8i_tfm_ctx *op = crypto_tfm_ctx(tfm);
	struct crypto_alg *alg = tfm->__crt_alg;
	struct sun8i_ss_alg_template *algt;

	memset(op, 0, sizeof(struct sun8i_tfm_ctx));

	algt = container_of(alg, struct sun8i_ss_alg_template, alg.crypto);
	op->ss = algt->ss;

	tfm->crt_ablkcipher.reqsize = sizeof(struct sun8i_cipher_req_ctx);

	op->fallback_tfm = crypto_alloc_blkcipher(crypto_tfm_alg_name(tfm),
			0, CRYPTO_ALG_ASYNC | CRYPTO_ALG_NEED_FALLBACK);
	if (IS_ERR(op->fallback_tfm)) {
		dev_err(op->ss->dev, "ERROR: Cannot allocate fallback\n");
		return PTR_ERR(op->fallback_tfm);
	}

	return 0;
}

void sun8i_ss_cipher_exit(struct crypto_tfm *tfm)
{
	struct sun8i_tfm_ctx *op = crypto_tfm_ctx(tfm);

	crypto_free_blkcipher(op->fallback_tfm);
}

int sun8i_ss_aes_setkey(struct crypto_ablkcipher *tfm, const u8 *key,
			unsigned int keylen)
{
	struct sun8i_tfm_ctx *op = crypto_ablkcipher_ctx(tfm);
	struct sun8i_ss_ctx *ss = op->ss;

	switch (keylen) {
	case 128 / 8:
		op->keymode = SS_AES_128BITS;
		break;
	case 192 / 8:
		op->keymode = SS_AES_192BITS;
		break;
	case 256 / 8:
		op->keymode = SS_AES_256BITS;
		break;
	default:
		dev_err(ss->dev, "ERROR: Invalid keylen %u\n", keylen);
		crypto_ablkcipher_set_flags(tfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
		return -EINVAL;
	}
	op->keylen = keylen;
	op->key = kzalloc(keylen, GFP_KERNEL);
	if (!op->key)
		return -ENOMEM;
	memcpy(op->key, key, keylen);

	return crypto_blkcipher_setkey(op->fallback_tfm, key, keylen);
}

int handle_cipher_request(struct crypto_engine *engine,
			  struct ablkcipher_request *breq)
{
	int err;

	err = sun8i_ss_cipher(breq);
	crypto_finalize_cipher_request(engine, breq, err);

	return 0;
}

