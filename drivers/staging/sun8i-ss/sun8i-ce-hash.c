/*
 * sun8i-ce-hash.c - hardware cryptographic accelerator for Allwinner H3/A64 SoC
 *
 * Copyright (C) 2015-2017 Corentin Labbe <clabbe.montjoie@gmail.com>
 *
 * This file add support for MD5 and SHA1/SHA224/SHA256/SHA384/SHA512.
 *
 * You could find the datasheet in Documentation/arm/sunxi/README
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include "sun8i-ss.h"
#include <linux/scatterlist.h>
#include <crypto/internal/hash.h>
#include <crypto/sha.h>
#include <crypto/md5.h>

/* This is a totally arbitrary value */
#define SS_TIMEOUT 100
#define SG_ZC 1

/*#define DEBUG*/
static int digest_size(struct ahash_request *areq)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(areq);
	struct ahash_alg *alg = __crypto_ahash_alg(tfm->base.__crt_alg);
	struct sun8i_ss_alg_template *algt;
	int digestsize;

	algt = container_of(alg, struct sun8i_ss_alg_template, alg.hash);
	digestsize = algt->alg.hash.halg.digestsize;
	if (digestsize == SHA224_DIGEST_SIZE)
		digestsize = SHA256_DIGEST_SIZE;
	if (digestsize == SHA384_DIGEST_SIZE)
		digestsize = SHA512_DIGEST_SIZE;
	return digestsize;
}

int sun8i_hash_crainit(struct crypto_tfm *tfm)
{
	struct sun8i_tfm_ctx *op = crypto_tfm_ctx(tfm);
	struct ahash_alg *alg = __crypto_ahash_alg(tfm->__crt_alg);
	struct sun8i_ss_alg_template *algt;

	memset(op, 0, sizeof(struct sun8i_tfm_ctx));

	algt = container_of(alg, struct sun8i_ss_alg_template, alg.hash);
	op->ss = algt->ss;

	crypto_ahash_set_reqsize(__crypto_ahash_cast(tfm),
				 sizeof(struct sun8i_hash_reqctx));

#ifdef DEBUG
	dev_info(op->ss->dev, "%s ====================\n", __func__);
#endif
	return 0;
}

int sun8i_hash_exit(struct ahash_request *areq)
{
/*	struct sun8i_hash_reqctx *op = ahash_request_ctx(areq);*/

/*	crypto_free_shash(op->fallback_tfm);*/
	return 0;
}

/* sun8i_hash_init: initialize request context */
int sun8i_hash_init(struct ahash_request *areq)
{
	struct sun8i_hash_reqctx *op = ahash_request_ctx(areq);
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(areq);
	struct ahash_alg *alg = __crypto_ahash_alg(tfm->base.__crt_alg);
	struct sun8i_ss_alg_template *algt;

	memset(op, 0, sizeof(struct sun8i_hash_reqctx));

	algt = container_of(alg, struct sun8i_ss_alg_template, alg.hash);
	op->mode = algt->mode;

	/* FALLBACK */
	/*
	op->fallback_tfm = crypto_alloc_shash(crypto_ahash_alg_name(tfm), 0,
		CRYPTO_ALG_NEED_FALLBACK);
	if (IS_ERR(op->fallback_tfm)) {
		dev_err(algt->ss->dev, "Fallback driver cound no be loaded\n");
		return PTR_ERR(op->fallback_tfm);
	}*/

	op->hash = kmalloc(digest_size(areq), GFP_KERNEL | GFP_ATOMIC);
	if (!op->hash)
		return -ENOMEM;
	/*dev_info(algt->ss->dev, "Alloc %p\n", op->hash);*/
	op->hash[0] = 0;
#ifdef DEBUG
	dev_info(algt->ss->dev, "%s ====================\n", __func__);
#endif

	return 0;
}

int sun8i_hash_export_md5(struct ahash_request *areq, void *out)
{
	struct sun8i_hash_reqctx *op = ahash_request_ctx(areq);
	struct md5_state *octx = out;
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(areq);
	struct ahash_alg *alg = __crypto_ahash_alg(tfm->base.__crt_alg);
	struct sun8i_ss_alg_template *algt;

	algt = container_of(alg, struct sun8i_ss_alg_template, alg.hash);

	octx->byte_count = op->byte_count + op->blen;

	if (op->blen > MD5_BLOCK_WORDS * 4) {
		pr_err("Cannot export MD5\n");
		return -EINVAL;
	}

	if (op->buf[0])
		memcpy(octx->block, op->buf[0], op->blen);

	if (op->byte_count > 0)
		memcpy(octx->hash, op->hash, MD5_BLOCK_WORDS);
	else
		memcpy(octx->hash, algt->hash_init, MD5_BLOCK_WORDS);

	return 0;
}

int sun8i_hash_import_md5(struct ahash_request *areq, const void *in)
{
	struct sun8i_hash_reqctx *op = ahash_request_ctx(areq);
	const struct md5_state *ictx = in;

	sun8i_hash_init(areq);

	op->byte_count = ictx->byte_count & ~0x3F;
	op->blen = ictx->byte_count & 0x3F;

	op->buf[0] = kzalloc(PAGE_SIZE, GFP_KERNEL | GFP_ATOMIC);
	if (!op->buf[0])
		return -ENOMEM;

	if (!op->sgbounce[0])
		op->sgbounce[0] = kzalloc(sizeof(*op->sgbounce[0]),
					  GFP_KERNEL | GFP_ATOMIC);
	if (!op->sgbounce[0])
		return -ENOMEM;

	sg_init_one(op->sgbounce[0], op->buf[0], PAGE_SIZE);

	if (op->blen)
		memcpy(op->buf[0], ictx->block, op->blen);
	memcpy(op->hash, ictx->hash, MD5_DIGEST_SIZE);

	return 0;
}

int sun8i_hash_export_sha1(struct ahash_request *areq, void *out)
{
	struct sun8i_hash_reqctx *op = ahash_request_ctx(areq);
	struct sha1_state *octx = out;
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(areq);
	struct ahash_alg *alg = __crypto_ahash_alg(tfm->base.__crt_alg);
	struct sun8i_ss_alg_template *algt;

	algt = container_of(alg, struct sun8i_ss_alg_template, alg.hash);

	if (op->blen > SHA1_DIGEST_SIZE * 4) {
		pr_err("Cannot export SHA1\n");
		return -EINVAL;
	}

	octx->count = op->byte_count + op->blen;

	memcpy(octx->buffer, op->buf[0], op->blen);

	if (op->byte_count > 0)
		memcpy(octx->state, op->hash, SHA1_DIGEST_SIZE);
	else
		memcpy(octx->state, algt->hash_init, SHA1_DIGEST_SIZE);

	return 0;
}

int sun8i_hash_import_sha1(struct ahash_request *areq, const void *in)
{
	struct sun8i_hash_reqctx *op = ahash_request_ctx(areq);
	const struct sha1_state *ictx = in;

	sun8i_hash_init(areq);

	op->byte_count = ictx->count & ~0x3F;
	op->blen = ictx->count & 0x3F;

	op->buf[0] = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!op->buf[0])
		return -ENOMEM;

	if (!op->sgbounce[0])
		op->sgbounce[0] = kzalloc(sizeof(*op->sgbounce[0]), GFP_KERNEL);
	if (!op->sgbounce[0])
		return -ENOMEM;

	sg_init_one(op->sgbounce[0], op->buf[0], PAGE_SIZE);

	if (op->blen)
		memcpy(op->buf[0], ictx->buffer, op->blen);

	memcpy(op->hash, ictx->state, SHA1_DIGEST_SIZE);

	return 0;
}

int sun8i_hash_export_sha256(struct ahash_request *areq, void *out)
{
	struct sun8i_hash_reqctx *op = ahash_request_ctx(areq);
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(areq);
	struct ahash_alg *alg = __crypto_ahash_alg(tfm->base.__crt_alg);
	struct sun8i_ss_alg_template *algt;
	struct sha256_state *octx = out;

	algt = container_of(alg, struct sun8i_ss_alg_template, alg.hash);

	if (op->blen > SHA224_DIGEST_SIZE * 4) {
		pr_err("Cannot export SHA224\n");
		return -EINVAL;
	}

	octx->count = op->byte_count + op->blen;
	if (op->blen)
		memcpy(octx->buf, op->buf[0], op->blen);

	if (op->byte_count > 0)
		memcpy(octx->state, op->hash, SHA256_DIGEST_SIZE);
	else
		memcpy(octx->state, algt->hash_init, SHA256_DIGEST_SIZE);

	return 0;
}

int sun8i_hash_import_sha256(struct ahash_request *areq, const void *in)
{
	struct sun8i_hash_reqctx *op = ahash_request_ctx(areq);
	const struct sha256_state *ictx = in;

	sun8i_hash_init(areq);

	op->byte_count = ictx->count & ~0x3F;
	op->blen = ictx->count & 0x3F;

	op->buf[0] = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!op->buf[0])
		return -ENOMEM;

	if (!op->sgbounce[0])
		op->sgbounce[0] = kzalloc(sizeof(*op->sgbounce[0]), GFP_KERNEL);
	if (!op->sgbounce[0])
		return -ENOMEM;

	sg_init_one(op->sgbounce[0], op->buf[0], PAGE_SIZE);

	if (op->blen)
		memcpy(op->buf[0], ictx->buf, op->blen);
	memcpy(op->hash, ictx->state, SHA256_DIGEST_SIZE);

	return 0;
}

int sun8i_hash_import_sha512(struct ahash_request *areq, const void *in)
{
	struct sun8i_hash_reqctx *op = ahash_request_ctx(areq);
	const struct sha512_state *ictx = in;

	sun8i_hash_init(areq);

	op->byte_count = ictx->count[0] & ~0x7F;
	op->blen = ictx->count[0] & 0x7F;

	op->byte_count2 = ictx->count[1];

	op->buf[0] = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!op->buf[0])
		return -ENOMEM;

	if (!op->sgbounce[0])
		op->sgbounce[0] = kzalloc(sizeof(*op->sgbounce[0]), GFP_KERNEL);
	if (!op->sgbounce[0])
		return -ENOMEM;

	sg_init_one(op->sgbounce[0], op->buf[0], PAGE_SIZE);

	if (op->blen)
		memcpy(op->buf[0], ictx->buf, op->blen);
	memcpy(op->hash, ictx->state, SHA512_DIGEST_SIZE);

	return 0;
}

int sun8i_hash_export_sha512(struct ahash_request *areq, void *out)
{
	struct sun8i_hash_reqctx *op = ahash_request_ctx(areq);
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(areq);
	struct ahash_alg *alg = __crypto_ahash_alg(tfm->base.__crt_alg);
	struct sun8i_ss_alg_template *algt;
	struct sha512_state *octx = out;

	algt = container_of(alg, struct sun8i_ss_alg_template, alg.hash);

	if (op->blen > SHA512_DIGEST_SIZE * 4) {
		pr_err("Cannot export SHA512\n");
		return -EINVAL;
	}

	octx->count[1] = op->byte_count2;
	octx->count[0] = op->byte_count + op->blen;
	if (octx->count[0] < op->blen)
		op->byte_count2++;

	if (op->blen)
		memcpy(octx->buf, op->buf[0], op->blen);

	if (op->byte_count > 0)
		memcpy(octx->state, op->hash, SHA512_DIGEST_SIZE);
	else
		memcpy(octx->state, algt->hash_init, SHA512_DIGEST_SIZE);
	return 0;
}

int sun8i_ss_do_task(struct ahash_request *areq, int j)
{
	struct sun8i_hash_reqctx *op = ahash_request_ctx(areq);
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(areq);
	struct sun8i_tfm_ctx *tfmctx = crypto_ahash_ctx(tfm);
	struct sun8i_ss_ctx *ss = tfmctx->ss;
	struct ahash_alg *alg = __crypto_ahash_alg(tfm->base.__crt_alg);
	struct sun8i_ss_alg_template *algt;
	struct ss_task *cet;
	int flow = 3;
	int nr_sgb, i, todo;
	struct scatterlist *sg;
	unsigned int len = j;
	int digestsize;
	u32 v;
	int sgnum = 0;
	int ret;

	flow = op->flow;
	/*dev_info(ss->dev, "Hash flow %d\n", flow);*/

#ifdef DEBUG
	dev_info(ss->dev, "%s %s %d\n", __func__, crypto_tfm_alg_name(areq->base.tfm), j);
#endif

	algt = container_of(alg, struct sun8i_ss_alg_template, alg.hash);
	digestsize = algt->alg.hash.halg.digestsize;
	if (digestsize == SHA224_DIGEST_SIZE)
		digestsize = SHA256_DIGEST_SIZE;
	if (digestsize == SHA384_DIGEST_SIZE)
		digestsize = SHA512_DIGEST_SIZE;

	cet = ss->tl[flow];
	memset(cet, 0, sizeof(struct ss_task));
	cet->t_id = flow;
	cet->t_common_ctl = op->mode | BIT(31);

	cet->t_dlen = j / 4;

	nr_sgb = op->cursg + 1;
	for (i = 0; i < nr_sgb; i++) {
		sg = op->sgbounce[i];
		if (!sg)
			break;
		/*dev_info(ss->dev, "DEBUG SG %d %p\n", i, op->buf[i]);*/
	}
	nr_sgb = op->cursg + 1;
	for (i = 0; i < nr_sgb; i++) {
		sg = op->sgbounce[i];
		if (!sg)
			break;
		/*dev_info(ss->dev, "SGmap %d\n", i);*/
		ret = dma_map_sg(ss->dev, sg, 1, DMA_TO_DEVICE);
		if (ret < 1)
			dev_err(ss->dev, "SG DMA MAP ERROR\n");
		cet->t_src[sgnum + i].addr = sg_dma_address(sg);
		todo = min(len, sg_dma_len(sg));
		cet->t_src[sgnum + i].len = todo / 4;
#ifdef DEBUG
		dev_info(ss->dev, "SG %d %u\n", sgnum + i, todo);
#endif
		len -= todo;
	}

	cet->t_dst[0].len = digestsize / 4;
	cet->t_dst[0].addr = dma_map_single(ss->dev, op->hash, cet->t_dst[0].len, DMA_FROM_DEVICE);
	if (dma_mapping_error(ss->dev, cet->t_dst[0].addr)) {
		dev_err(ss->dev, "Cannot DMA MAP RESULT\n");
	}

	/* TODO need to do a flag for non std IV */
	if (op->hash[0] != 0) {
		ss->chanlist[flow].bounce_iv = kmalloc(digestsize, GFP_KERNEL | GFP_DMA);
		ss->chanlist[flow].ivlen = digestsize;
		cet->t_common_ctl |= BIT(16);
		memcpy(ss->chanlist[flow].bounce_iv, op->hash, digestsize);
	}
	ret = sun8i_ce_run_task(ss, flow, "hash");
	if (op->hash[0] != 0) {
		kzfree(ss->chanlist[flow].bounce_iv);
		ss->chanlist[flow].bounce_iv = NULL;
	}

	for (i = 0; i < nr_sgb; i++) {
		sg = op->sgbounce[i];
		if (!sg)
			break;
		dma_unmap_sg(ss->dev, sg, 1, DMA_TO_DEVICE);
	}

	dma_unmap_single(ss->dev, cet->t_dst[0].addr, cet->t_dst[0].len,
			 DMA_FROM_DEVICE);

	v = readl(ss->base + CE_ESR);
	if (v) {
		dev_err(ss->dev, "CE ERROR %x %x\n", v, v >> flow * 4);
	}
	/*dev_info(ss->dev, "Fin Upload %d %u %p %p\n", op->blen, areq->nbytes,
	 * op->buf, op->hash);*/
	return ret;
}

#define SS_HASH_UPDATE 1
#define SS_HASH_FINAL 2

/* Fill op->sgbounce with sg from areq->src
 * skip "skip" sg */
int sun8i_ss_hashtask_zc(struct ahash_request *areq)
{
	struct sun8i_hash_reqctx *op = ahash_request_ctx(areq);
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(areq);
	struct sun8i_tfm_ctx *tfmctx = crypto_ahash_ctx(tfm);
	struct sun8i_ss_ctx *ss = tfmctx->ss;

	int i = op->cursg;
	int zlen = 0;

	if (!op->src_sg) {
		dev_err(ss->dev, "SG is NULL\n");
		return -EINVAL;
	}

	do {
		op->sgbounce[i] = op->src_sg;
		op->sgflag[i] = SG_ZC;
		zlen += op->src_sg->length;
#ifdef DEBUG
		dev_info(ss->dev, "ZCMap %d %u\n", i, op->src_sg->length);
#endif
		op->src_sg = sg_next(op->src_sg);
		i++;
		/* TODO round zlen to bs */
		if (i > 7 && zlen > 64) {
			op->cursg = i;
			sun8i_ss_do_task(areq, zlen);

			i = 0;
			op->sgbounce[i] = NULL;
			op->byte_count += zlen;
			zlen = 0;
			op->cursg = 0;
		}
		if (i > 7) {
			dev_err(ss->dev, "%s Trop de SG\n", __func__);
			return 0;
		}
	} while (op->src_sg);
	op->cursg = i;

#ifdef DEBUG
	dev_info(ss->dev, "%s end with cursg=%d\n", __func__, i);
#endif
	return 0;
}

/* copy data in a compact sg
 * copy data from areq->src offset ???
 * to op->sgbounce on sg=op->cursg
 */
int sun8i_ss_hashtask_bounce(struct ahash_request *areq)
{
	struct sun8i_hash_reqctx *op = ahash_request_ctx(areq);
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(areq);
	struct sun8i_tfm_ctx *tfmctx = crypto_ahash_ctx(tfm);
	struct sun8i_ss_ctx *ss = tfmctx->ss;
	struct ahash_alg *alg = __crypto_ahash_alg(tfm->base.__crt_alg);
	struct sun8i_ss_alg_template *algt;
	int cursg = 0;
	int offset;
	int bs = 64;/* TODO */
	unsigned long j;
	unsigned long tocopy = 0;
	int i;

	int sg_src_offset = 0;
	/* sg_src_len: how many bytes remains in SG src */
	unsigned int sg_src_len = areq->nbytes;
	unsigned long copied, max;

	algt = container_of(alg, struct sun8i_ss_alg_template, alg.hash);
	bs = algt->alg.hash.halg.base.cra_blocksize;

start_copy:
	/* in which sg we need to copy ? */
	cursg = op->blen / PAGE_SIZE;
	cursg = op->cursg;
	offset = op->blen % PAGE_SIZE;

	if (cursg > 7) {
		dev_err(ss->dev, "ERROR: MAXIMUM SG\n");
		return -EINVAL;
	}

/*	if (cursg == 0 && offset == 0 && !op->buf[0])
		sg_init_table(op->sgbounce, 8);*/

	if (!op->buf[cursg]) {
		/*dev_info(ss->dev, "Allocate SG %d\n", cursg);*/
		if (!op->sgbounce[cursg])
			op->sgbounce[cursg] = kzalloc(sizeof(*op->sgbounce[cursg]),
						      GFP_KERNEL | GFP_ATOMIC);
		if (!op->sgbounce[cursg])
			return -ENOMEM;

		op->buf[cursg] = kzalloc(PAGE_SIZE, GFP_KERNEL | GFP_ATOMIC);
		if (!op->buf[cursg])
			return -ENOMEM;
		sg_init_one(op->sgbounce[cursg], op->buf[cursg], PAGE_SIZE);
	}

	if (areq->nbytes == 0)
		return 0;

	/* if the request is not final, we need to round to bs */
	if ((op->flags & SS_HASH_FINAL) == 0 && sg_src_len + op->blen > bs)
		max = ((sg_src_len + op->blen) / bs) * bs - op->blen;
	else
		max = sg_src_len;

	tocopy = min(max, PAGE_SIZE - offset);

	if (tocopy == 0) {
#ifdef DEBUG
		dev_info(ss->dev, "Nocopy %d (sg %d) (src offset %d/%u) %lu %lu\n",
			 offset, cursg, sg_src_offset, areq->nbytes, max, tocopy);
#endif
		return 0;
	}

	copied = sg_pcopy_to_buffer(op->src_sg, sg_nents(op->src_sg),
				    op->buf[cursg] + offset, tocopy,
				    sg_src_offset);
#ifdef DEBUG
	dev_info(ss->dev, "Copied %lu at %d (sg %d) (src offset %d/%u) %lu %lu sgsrclen=%u\n",
		 copied, offset, cursg, sg_src_offset, areq->nbytes, max, tocopy, sg_src_len);
#endif
	sg_src_len -= copied;
	sg_src_offset += copied;
	op->blen += copied;
	if (op->blen % PAGE_SIZE == 0)
		op->cursg++;

	/* maximum supported by hw */
	if (cursg == 7 && op->blen == PAGE_SIZE) {
#ifdef DEBUG
		dev_info(ss->dev, "NEED UPLOAD (MAXIMUM)\n");
#endif
	}

	if (sg_src_len > bs)
		goto start_copy;

	if (op->blen >= bs && (op->flags & SS_HASH_FINAL) == 0) {
		j = op->blen - op->blen % bs;
#ifdef DEBUG
		dev_info(ss->dev, "NEED UPLOAD %lu sg_src_len=%d\n", j, sg_src_len);
#endif
		/*sg_mark_end(op->sgbounce[cursg]);*/
		sun8i_ss_do_task(areq, j);
		op->cursg = 0;
		op->byte_count += j;
		memset(op->buf[0], 0, PAGE_SIZE);
		/*sg_init_table(op->sgbounce, 8);*/
		for (i = 0; i < 8; i++) {
			if (op->buf[i]) {
				memset(op->sgbounce[i], 0, sizeof(struct scatterlist));
				sg_init_one(op->sgbounce[i], op->buf[i], PAGE_SIZE);
			}
		}
		op->blen = 0;
	}

	if (sg_src_len > 0)
		goto start_copy;

	op->cursg = cursg;

#ifdef DEBUG
	dev_info(ss->dev, "%s end %llu %lu\n", __func__, op->byte_count, op->blen);
#endif
	return 0;
}

/*
 * sun8i_hash_update: update hash engine
 *
 * Could be used for both SHA1 and MD5
 * Write data by step of 32bits and put then in the SS.
 *
 * Since we cannot leave partial data and hash state in the engine,
 * we need to get the hash state at the end of this function.
 * We can get the hash state every 64 bytes
 *
 * So the first work is to get the number of bytes to write to SS modulo 64
 * The extra bytes will go to a temporary buffer op->buf storing op->blen bytes
 *
 * So at the begin of update()
 * if op->blen + areq->nbytes < 64
 * => all data will be written to wait buffer (op->buf) and end=0
 * if not, write all data from op->buf to the device and position end to
 * complete to 64bytes
 *
 * example 1:
 * update1 60o => op->blen=60
 * update2 60o => need one more word to have 64 bytes
 * end=4
 * so write all data from op->buf and one word of SGs
 * write remaining data in op->buf
 * final state op->blen=56
 */
int sun8i_hash(struct ahash_request *areq)
{
	struct sun8i_hash_reqctx *op = ahash_request_ctx(areq);
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(areq);
	struct sun8i_tfm_ctx *tfmctx = crypto_ahash_ctx(tfm);
	struct sun8i_ss_ctx *ss = tfmctx->ss;
	struct ahash_alg *alg = __crypto_ahash_alg(tfm->base.__crt_alg);
	struct sun8i_ss_alg_template *algt;
	int err = 0;
	int no_chunk = 1;
	struct scatterlist *sg;
	unsigned int index, padlen;
	int j;
	int zeros;
	__be64 bits;
	int digestsize;
	int bs = 64;
	int cursg;
	int i;
	int rawdata = 0;

	algt = container_of(alg, struct sun8i_ss_alg_template, alg.hash);
	digestsize = algt->alg.hash.halg.digestsize;
	if (digestsize == SHA224_DIGEST_SIZE)
		digestsize = SHA256_DIGEST_SIZE;
	if (digestsize == SHA384_DIGEST_SIZE)
		digestsize = SHA512_DIGEST_SIZE;
	bs = algt->alg.hash.halg.base.cra_blocksize;

	if (!op->src_sg)
		op->src_sg = areq->src;

	i = sg_nents(op->src_sg);
	if (i > 7) {
		dev_err(ss->dev, "MAXIMUM SG %d\n", i);
		return -EINVAL;
	}

#ifdef DEBUG
	dev_info(ss->dev, "%s nbytes=%u flags=%x blen=%lu %s\n", __func__, areq->nbytes,
		 op->flags, op->blen, crypto_tfm_alg_name(areq->base.tfm));
#endif

	if ((op->flags & SS_HASH_UPDATE) == 0)
		goto hash_final2;

	/* If we cannot work on a full block and more data could come, bounce data */
	if (op->blen + areq->nbytes < bs && (op->flags & SS_HASH_FINAL) == 0)
		return sun8i_ss_hashtask_bounce(areq);

	/* does the data need to be bounced ? */
	sg = op->src_sg;
	while (sg && no_chunk == 1) {
		if ((sg->length % 4) != 0)
			no_chunk = 0;
		if (!IS_ALIGNED(sg->offset, sizeof(u32))) {
#ifdef DEBUG
			dev_info(ss->dev, "Align problem on src\n");
#endif
			no_chunk = 0;
		}
		sg = sg_next(sg);
	}

	if (no_chunk == 0 || areq->nbytes == 0 || (areq->nbytes % bs != 0) || op->blen > 0) {
		sun8i_ss_hashtask_bounce(areq);
	} else {
		sun8i_ss_hashtask_zc(areq);
		if (areq->nbytes >= bs && (op->flags & SS_HASH_FINAL) == 0) {
			op->cursg--;
			j = areq->nbytes - areq->nbytes % bs;
#ifdef DEBUG
			dev_info(ss->dev, "Will upload %d of %u\n", j, areq->nbytes);
#endif
			sun8i_ss_do_task(areq, j);
			if (op->buf[0])
				memset(op->buf[0], 0, PAGE_SIZE);
			op->cursg = 0;
			op->byte_count += j;
			op->blen = 0;
			for (i = 0; i < 8; i++) {
				/*dev_info(ss->dev, "Clean %d f=%d %p %p\n", i, op->sgflag[i], op->buf[i], op->sgbounce[i]);*/
				/* If sg is a bounce sg, zero it*/
				if (op->buf[i] && op->sgflag[i] == 0) {
					if (op->sgbounce[i]) {
						memset(op->sgbounce[i], 0, sizeof(struct scatterlist));
						sg_init_one(op->sgbounce[i],
							   op->buf[i], PAGE_SIZE);
					}
				} else {
					op->sgflag[i] = 0;
				}
			}
			return 0;
		}
		/*op->blen = areq->nbytes;*/
		rawdata = areq->nbytes; /*TODO a retablir avec le zc ?*/
	}
/*
	if (op->blen >= bs && (op->flags & SS_HASH_FINAL) == 0) {
		j = op->blen - op->blen % bs;
		dev_info(ss->dev, "Will upload %d of %lu\n", j, op->blen);
	}*/

	if ((op->flags & SS_HASH_FINAL) == 0)
		return 0;

hash_final2:

	cursg = op->blen / PAGE_SIZE;
	cursg = op->cursg;
	if (!op->buf[cursg]) {
		/*dev_err(ss->dev, "No buffer on sg %d\n", cursg);*/
		op->buf[cursg] = kzalloc(PAGE_SIZE, GFP_KERNEL | GFP_ATOMIC);
		if (!op->buf[cursg])
			return -ENOMEM;
		if (!op->sgbounce[cursg])
			op->sgbounce[cursg] = kzalloc(sizeof(*op->sgbounce[cursg]),
						      GFP_KERNEL | GFP_ATOMIC);
		if (!op->sgbounce[cursg])
			return -ENOMEM;
		sg_init_one(op->sgbounce[cursg], op->buf[cursg], PAGE_SIZE);
		/*dev_info(ss->dev, "Alloc SG %d %lu\n", cursg, PAGE_SIZE);*/
		/*return -EINVAL;*/
	}

	j = op->blen;
	op->byte_count += (op->blen / 4) * 4 + rawdata;
	op->buf[cursg][j] = 1 << 7;
	j += 4;

	if (op->mode == CE_OP_MD5 || op->mode == CE_OP_SHA1 ||
	    op->mode == CE_OP_SHA224 || op->mode == CE_OP_SHA256) {
		index = (op->byte_count + 4) & 0x3f;
		op->byte_count += op->blen % 4;
		padlen = (index < 56) ? (56 - index) : (120 - index);
		zeros = padlen;
	} else {
		op->byte_count += op->blen % 4;
		index = (op->byte_count + 4) & 0x7f;
		padlen = (index < 112) ? (112 - index) : (240 - index);
		zeros = padlen;
	}
	/*memset(op->buf + j, 0, zeros);*/
	j += zeros;

	/* TODO use switch */
	if (op->mode == CE_OP_MD5) {
		((u32 *)op->buf[cursg])[j / 4] = (op->byte_count << 3) & 0xffffffff;
		j += 4;
		((u32 *)op->buf[cursg])[j / 4] = (op->byte_count >> 29) & 0xffffffff;
		j += 4;
	} else {
		if (op->mode == CE_OP_SHA1 || op->mode == CE_OP_SHA224 ||
		    op->mode == CE_OP_SHA256) {
			bits = cpu_to_be64(op->byte_count << 3);
			((u32 *)op->buf[cursg])[j / 4] = bits & 0xffffffff;
			j += 4;
			((u32 *)op->buf[cursg])[j / 4] = (bits >> 32) & 0xffffffff;
			j += 4;
		} else {
			bits = cpu_to_be64(op->byte_count >> 61 | op->byte_count2 << 3);
			((u32 *)op->buf[cursg])[j / 4] = bits & 0xffffffff;
			j += 4;
			((u32 *)op->buf[cursg])[j / 4] = (bits >> 32) & 0xffffffff;
			j += 4;
			bits = cpu_to_be64(op->byte_count << 3);
			((u32 *)op->buf[cursg])[j / 4] = bits & 0xffffffff;
			j += 4;
			((u32 *)op->buf[cursg])[j / 4] = (bits >> 32) & 0xffffffff;
			j += 4;
		}
	}

	/*dev_info(ss->dev, "Plop j=%d rawdata=%d\n", j, rawdata);*/
	sun8i_ss_do_task(areq, j + rawdata);

	if ((op->flags & SS_HASH_FINAL) == 0) {
		op->byte_count += j;
		memset(op->buf[0], 0, PAGE_SIZE);
		/*sg_init_table(op->sgbounce, 8);*/
		for (i = 0; i < 8; i++) {
			if (op->buf[i]) {
				memset(op->sgbounce[i], 0,
				       sizeof(struct scatterlist));
				sg_init_one(op->sgbounce[i], op->buf[i],
					    PAGE_SIZE);
			}
		}
		op->blen = 0;
	} else {
		memcpy(areq->result, op->hash, digestsize);
		/* clean allocated */
		/*dev_info(ss->dev, "Clean %p\n", op->hash);*/
		kfree(op->hash);
		op->hash = NULL;
		for (i = 0; i < 8; i++) {
			kfree(op->buf[i]);
			op->buf[i] = NULL;
		}
	}

	return err;
}

int sun8i_hash_final(struct ahash_request *areq)
{
	struct sun8i_hash_reqctx *op = ahash_request_ctx(areq);
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(areq);
	struct sun8i_tfm_ctx *tfmctx = crypto_ahash_ctx(tfm);
	struct sun8i_ss_ctx *ss = tfmctx->ss;
	int e = get_engine_number(ss);

	op->flow = e;
	op->flags = SS_HASH_FINAL;
	return crypto_transfer_hash_request_to_engine(ss->engines[e], areq);
}

int sun8i_hash_update(struct ahash_request *areq)
{
	struct sun8i_hash_reqctx *op = ahash_request_ctx(areq);
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(areq);
	struct sun8i_tfm_ctx *tfmctx = crypto_ahash_ctx(tfm);
	struct sun8i_ss_ctx *ss = tfmctx->ss;
	int e = get_engine_number(ss);

	op->flow = e;
	op->flags = SS_HASH_UPDATE;
	return crypto_transfer_hash_request_to_engine(ss->engines[e], areq);
	return sun8i_hash(areq);
}

/* sun8i_hash_finup: finalize hashing operation after an update */
int sun8i_hash_finup(struct ahash_request *areq)
{
	struct sun8i_hash_reqctx *op = ahash_request_ctx(areq);
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(areq);
	struct sun8i_tfm_ctx *tfmctx = crypto_ahash_ctx(tfm);
	struct sun8i_ss_ctx *ss = tfmctx->ss;
	int e = get_engine_number(ss);

	op->flow = e;
	op->flags = SS_HASH_UPDATE | SS_HASH_FINAL;
	return crypto_transfer_hash_request_to_engine(ss->engines[e], areq);
	return sun8i_hash(areq);
}

/* combo of init/update/final functions */
int sun8i_hash_digest(struct ahash_request *areq)
{
	int err;
	struct sun8i_hash_reqctx *op = ahash_request_ctx(areq);
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(areq);
	struct sun8i_tfm_ctx *tfmctx = crypto_ahash_ctx(tfm);
	struct sun8i_ss_ctx *ss = tfmctx->ss;
	int e = get_engine_number(ss);

	err = sun8i_hash_init(areq);
	if (err != 0)
		return err;

	op->flow = e;
	op->flags = SS_HASH_UPDATE | SS_HASH_FINAL;
	return crypto_transfer_hash_request_to_engine(ss->engines[e], areq);
	return sun8i_hash(areq);
}
