/*
 * sun8i-ce-core.c - hardware cryptographic accelerator for Allwinner H3/A64 SoC
 *
 * Copyright (C) 2015-2017 Corentin Labbe <clabbe.montjoie@gmail.com>
 *
 * Core file which registers crypto algorithms supported by the CryptoEngine.
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
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <crypto/scatterwalk.h>
#include <linux/scatterlist.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/reset.h>
#include <crypto/sha.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/akcipher.h>
#include <crypto/internal/skcipher.h>
#include <linux/dma-mapping.h>

#include "sun8i-ss.h"

static const struct ce_variant ce_h3_variant = {
	.alg_hash = { CE_ID_NOTSUPP, CE_OP_MD5, CE_OP_SHA1, CE_OP_SHA224,
		CE_OP_SHA256, CE_OP_SHA384, CE_OP_SHA512,
	},
	.alg_cipher = { CE_ID_NOTSUPP, CE_OP_AES, CE_OP_DES, CE_OP_3DES, },
	.op_mode = { CE_ID_NOTSUPP, CE_ECB, CE_CBC, CE_ID_NOTSUPP,
		CE_ID_NOTSUPP, CE_ID_NOTSUPP, CE_ID_NOTSUPP, CE_ID_NOTSUPP
	},
	.prng = CE_OP_PRNG,
	.trng = CE_ID_NOTSUPP,
};

static const struct ce_variant ce_a64_variant = {
	.alg_hash = { CE_ID_NOTSUPP, CE_OP_MD5, CE_OP_SHA1, CE_OP_SHA224,
		CE_OP_SHA256, CE_ID_NOTSUPP, CE_ID_NOTSUPP,
	},
	.alg_cipher = { CE_ID_NOTSUPP, CE_OP_AES, CE_OP_DES, CE_OP_3DES, },
	.op_mode = { CE_ID_NOTSUPP, CE_ECB, CE_CBC, CE_ID_NOTSUPP,
		CE_ID_NOTSUPP, CE_ID_NOTSUPP, CE_ID_NOTSUPP, CE_ID_NOTSUPP
	},
	.prng = CE_OP_PRNG,
	.trng = CE_ID_NOTSUPP,
};

static const struct ce_variant ce_a83t_variant = {
	.alg_hash = { CE_ID_NOTSUPP, SS_OP_MD5, SS_OP_SHA1, SS_OP_SHA224,
		SS_OP_SHA256, CE_ID_NOTSUPP, CE_ID_NOTSUPP,
	},
	.alg_cipher = { CE_ID_NOTSUPP, SS_OP_AES, SS_OP_DES, SS_OP_3DES, },
	.op_mode = { CE_ID_NOTSUPP, CE_ID_NOTSUPP, SS_CBC, CE_ID_NOTSUPP,
		CE_ID_NOTSUPP, CE_ID_NOTSUPP, CE_ID_NOTSUPP, CE_ID_NOTSUPP
	},
	.prng = SS_OP_PRNG,
	.trng = CE_ID_NOTSUPP,
	.is_ss = true,
};

static const u32 ce_md5_init[MD5_DIGEST_SIZE / 4] = {
	MD5_H0, MD5_H1, MD5_H2, MD5_H3
};

static const u32 ce_sha1_init[SHA1_DIGEST_SIZE / 4] = {
	cpu_to_be32(SHA1_H0), cpu_to_be32(SHA1_H1),
	cpu_to_be32(SHA1_H2), cpu_to_be32(SHA1_H3),
	cpu_to_be32(SHA1_H4),
};

static const u32 ce_sha224_init[SHA256_DIGEST_SIZE / 4] = {
	cpu_to_be32(SHA224_H0), cpu_to_be32(SHA224_H1),
	cpu_to_be32(SHA224_H2), cpu_to_be32(SHA224_H3),
	cpu_to_be32(SHA224_H4), cpu_to_be32(SHA224_H5),
	cpu_to_be32(SHA224_H6), cpu_to_be32(SHA224_H7),
};

static const u32 ce_sha256_init[SHA256_DIGEST_SIZE / 4] = {
	cpu_to_be32(SHA256_H0), cpu_to_be32(SHA256_H1),
	cpu_to_be32(SHA256_H2), cpu_to_be32(SHA256_H3),
	cpu_to_be32(SHA256_H4), cpu_to_be32(SHA256_H5),
	cpu_to_be32(SHA256_H6), cpu_to_be32(SHA256_H7),
};

static const u64 ce_sha384_init[SHA512_DIGEST_SIZE / 8] = {
	cpu_to_be64(SHA384_H0), cpu_to_be64(SHA384_H1),
	cpu_to_be64(SHA384_H2), cpu_to_be64(SHA384_H3),
	cpu_to_be64(SHA384_H4), cpu_to_be64(SHA384_H5),
	cpu_to_be64(SHA384_H6), cpu_to_be64(SHA384_H7),
};

static const u64 ce_sha512_init[SHA512_DIGEST_SIZE / 8] = {
	cpu_to_be64(SHA512_H0), cpu_to_be64(SHA512_H1),
	cpu_to_be64(SHA512_H2), cpu_to_be64(SHA512_H3),
	cpu_to_be64(SHA512_H4), cpu_to_be64(SHA512_H5),
	cpu_to_be64(SHA512_H6), cpu_to_be64(SHA512_H7),
};

int get_engine_number(struct sun8i_ss_ctx *ss)
{
	int e = ss->flow;

	ss->flow++;
	if (ss->flow >= MAXCHAN)
		ss->flow = 0;

	return e;
}

int sun8i_ss_run_task(struct sun8i_ss_ctx *ss, int flow, const char *name)
{
	int err = 0;
	u32 v = 1;
	struct ss_task *cet = ss->tl[flow];
	int i;

	/* choose between stream0/stream1 */
	if (flow)
		v |= BIT(31);
	else
		v |= BIT(30);

	v |= ss->chanlist[flow].op_mode;
	v |= ss->chanlist[flow].method;
	v |= ss->chanlist[flow].op_dir;

	switch (ss->chanlist[flow].keylen) {
	case 192 / 8:
		v |= SS_AES_192BITS << 7;
	break;
	case 256 / 8:
		v |= SS_AES_256BITS << 7;
	break;
	}

	/* enable INT */
	writel(BIT(flow), ss->base + SS_INT_CTL_REG);

	writel(cet->t_key, ss->base + SS_KEY_ADR_REG);
	writel(cet->t_iv, ss->base + SS_IV_ADR_REG);

	for (i = 0; i < 8; i++) {
		if (!cet->t_src[i].addr)
			break;
		dev_info(ss->dev, "Processing SG %d\n", i);
		writel(cet->t_src[i].addr, ss->base + SS_SRC_ADR_REG);
		writel(cet->t_dst[i].addr, ss->base + SS_DST_ADR_REG);
		writel(cet->t_dst[i].len, ss->base + SS_LEN_ADR_REG);
		writel(v, ss->base + SS_CTL_REG);
	}

	return err;
}
int sun8i_ce_run_task(struct sun8i_ss_ctx *ss, int flow, const char *name)
{
	u32 v;
	int err = 0;
	struct ss_task *cet = ss->tl[flow];

	if (ss->chanlist[flow].bounce_iv) {
		cet->t_iv = dma_map_single(ss->dev,
					   ss->chanlist[flow].bounce_iv,
					   ss->chanlist[flow].ivlen,
					   DMA_BIDIRECTIONAL);
		if (dma_mapping_error(ss->dev, cet->t_iv)) {
			dev_err(ss->dev, "Cannot DMA MAP IV\n");
			return -EFAULT;
		}
	}
	if (ss->chanlist[flow].next_iv) {
		cet->t_ctr = dma_map_single(ss->dev,
					    ss->chanlist[flow].next_iv,
					    ss->chanlist[flow].ivlen,
					    DMA_FROM_DEVICE);
		if (dma_mapping_error(ss->dev, cet->t_ctr)) {
			dev_err(ss->dev, "Cannot DMA MAP IV\n");
			err = -EFAULT;
			goto err_next_iv;
		}
	}

	mutex_lock(&ss->mlock);

	v = readl(ss->base + CE_ICR);
	v |= 1 << flow;
	writel(v, ss->base + CE_ICR);

	reinit_completion(&ss->chanlist[flow].complete);
	writel(ss->ce_t_phy[flow], ss->base + CE_TDQ);

	ss->chanlist[flow].status = 0;
	/* Be sure all data is written before enabling the task */
	wmb();

	writel(1, ss->base + CE_TLR);
	mutex_unlock(&ss->mlock);

	wait_for_completion_interruptible_timeout(&ss->chanlist[flow].complete,
						  msecs_to_jiffies(5000));

	if (ss->chanlist[flow].status == 0) {
		dev_err(ss->dev, "DMA timeout for %s\n", name);
		err = -EINVAL;
	}

	v = readl(ss->base + CE_ESR);
	if (v) {
		dev_err(ss->dev, "CE ERROR %x\n", v);
		err = -EFAULT;
	}

	if (ss->chanlist[flow].next_iv) {
		dma_unmap_single(ss->dev, cet->t_ctr,
				 ss->chanlist[flow].ivlen,
				 DMA_FROM_DEVICE);
	}
err_next_iv:
	if (ss->chanlist[flow].bounce_iv) {
		dma_unmap_single(ss->dev, cet->t_iv,
				 ss->chanlist[flow].ivlen,
				 DMA_BIDIRECTIONAL);
	}

	return err;
}

/* compact an sglist to a more "compact" sglist
 * With a maximum of 8 SGs
 * */
int sun8i_ss_compact(struct scatterlist *sg, unsigned int len)
{
	int numsg;
	struct scatterlist *sglist;
	int i;
	void *buf;
	unsigned int offset = 0;
	int copied;

	/* determine the number of sgs necessary */
	numsg = len / PAGE_SIZE + 1;
	if (numsg > 8)
		return -EINVAL;
	sglist = kcalloc(numsg, sizeof(struct scatterlist), GFP_KERNEL);
	if (!sglist)
		return -ENOMEM;
	sg_init_table(sglist, numsg);
	for (i = 0; i < numsg; i++) {
		buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
		if (!buf)
			return -ENOMEM;
		sg_set_buf(&sglist[i], buf, PAGE_SIZE);
		copied = sg_pcopy_to_buffer(sg, sg_nents(sg), buf, PAGE_SIZE,
					    offset);
		pr_info("%d Copied %d at %u\n", i, copied, offset);
		offset += copied;
	}
	return 0;
}

/* copy all data from an sg to a plain buffer for channel flow */
int sun8i_ss_bounce_src(struct ablkcipher_request *areq, int flow)
{
	struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(areq);
	struct sun8i_tfm_ctx *op = crypto_ablkcipher_ctx(tfm);
	struct sun8i_ss_ctx *ss = op->ss;

	if (areq->nbytes > PAGE_SIZE)
		return -EINVAL;

	ss->chanlist[flow].bufsrc = kmalloc(areq->nbytes, GFP_KERNEL);
	if (!ss->chanlist[flow].bufsrc)
		return -ENOMEM;

	sg_copy_to_buffer(areq->src, sg_nents(areq->src),
			  ss->chanlist[flow].bufsrc, areq->nbytes);

	ss->chanlist[flow].bounce_src = kcalloc(1, sizeof(struct scatterlist),
						GFP_KERNEL);
	if (!ss->chanlist[flow].bounce_src)
		return -ENOMEM;

	sg_init_table(ss->chanlist[flow].bounce_src, 1);
	sg_set_buf(ss->chanlist[flow].bounce_src, ss->chanlist[flow].bufsrc,
		   areq->nbytes);

	return 0;
}

/* create a destination bounce buffer */
int sun8i_ss_bounce_dst(struct ablkcipher_request *areq, int flow)
{
	struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(areq);
	struct sun8i_tfm_ctx *op = crypto_ablkcipher_ctx(tfm);
	struct sun8i_ss_ctx *ss = op->ss;

	if (areq->nbytes > PAGE_SIZE)
		return -EINVAL;

	ss->chanlist[flow].bufdst = kmalloc(areq->nbytes, GFP_KERNEL);
	if (!ss->chanlist[flow].bufdst)
		return -ENOMEM;

	ss->chanlist[flow].bounce_dst = kcalloc(1, sizeof(struct scatterlist),
						GFP_KERNEL);
	if (!ss->chanlist[flow].bounce_dst)
		return -ENOMEM;

	sg_init_table(ss->chanlist[flow].bounce_dst, 1);
	sg_set_buf(ss->chanlist[flow].bounce_dst, ss->chanlist[flow].bufdst,
		   areq->nbytes);

	return 0;
}

int handle_hash_request(struct crypto_engine *engine,
			struct ahash_request *areq)
{
	int err;

	err = sun8i_hash(areq);
	crypto_finalize_hash_request(engine, areq, err);

	return 0;
}

irqreturn_t ss_irq_handler(int irq, void *data)
{
	u32 p;
	struct sun8i_ss_ctx *ss = (struct sun8i_ss_ctx *)data;
	int flow = 0;

	p = readl(ss->base + SS_INT_STA_REG);
	for (flow = 0; flow < 2; flow++) {
		if (p & BIT(flow)) {
			writel(BIT(flow), ss->base + SS_INT_STA_REG);
			ss->chanlist[flow].status = 1;
			complete(&ss->chanlist[flow].complete);
		}
	}

	return IRQ_HANDLED;
}

irqreturn_t ce_irq_handler(int irq, void *data)
{
	u32 p;
	struct sun8i_ss_ctx *ss = (struct sun8i_ss_ctx *)data;
	int flow = 0;

	p = readl(ss->base + CE_ISR);
	/*dev_info(ss->dev, "%s %d, %x\n", __func__, irq, p);*/
	for (flow = 0; flow < MAXCHAN; flow++) {
		if (p & (1 << flow)) {
			writel(1 << flow, ss->base + CE_ISR);
			/*dev_info(ss->dev, "Acked %d\n", flow);*/
			ss->chanlist[flow].status = 1;
			complete(&ss->chanlist[flow].complete);
		}
	}

	return IRQ_HANDLED;
}

static struct sun8i_ss_alg_template ss_algs[] = {
{	.type = CRYPTO_ALG_TYPE_ABLKCIPHER,
	.ce_algo_id = CE_ID_CIPHER_AES,
	.ce_blockmode = CE_ID_MODE_CBC,
	.alg.crypto = {
		.cra_name = "cbc(aes)",
		.cra_driver_name = "cbc-aes-sun8i-ss",
		.cra_priority = 300,
		.cra_blocksize = AES_BLOCK_SIZE,
		.cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC |
			CRYPTO_ALG_NEED_FALLBACK,
		.cra_ctxsize = sizeof(struct sun8i_tfm_ctx),
		.cra_module = THIS_MODULE,
		.cra_alignmask = 3,
		.cra_type = &crypto_ablkcipher_type,
		.cra_init = sun8i_ss_cipher_init,
		.cra_exit = sun8i_ss_cipher_exit,
		.cra_ablkcipher = {
			.min_keysize	= AES_MIN_KEY_SIZE,
			.max_keysize	= AES_MAX_KEY_SIZE,
			.ivsize		 = AES_BLOCK_SIZE,
			.setkey		 = sun8i_ss_aes_setkey,
			.encrypt		= sun8i_ss_cbc_aes_encrypt,
			.decrypt		= sun8i_ss_cbc_aes_decrypt,
		}
	}
},
{	.type = CRYPTO_ALG_TYPE_AHASH,
	.mode = CE_OP_MD5,
	.ce_algo_id = CE_ID_HASH_MD5,
	.hash_init = ce_md5_init,
	.alg.hash = {
		.init = sun8i_hash_init,
		.update = sun8i_hash_update,
		.final = sun8i_hash_final,
		.finup = sun8i_hash_finup,
		.digest = sun8i_hash_digest,
		.export = sun8i_hash_export_md5,
		.import = sun8i_hash_import_md5,
		.halg = {
			.digestsize = MD5_DIGEST_SIZE,
			.statesize = sizeof(struct md5_state),
			.base = {
				.cra_name = "md5",
				.cra_driver_name = "md5-sun8i-ss",
				.cra_priority = 300,
				.cra_alignmask = 3,
				.cra_flags = CRYPTO_ALG_TYPE_AHASH |
					CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_NEED_FALLBACK,
				.cra_blocksize = MD5_HMAC_BLOCK_SIZE,
				.cra_ctxsize = sizeof(struct sun8i_hash_reqctx),
				.cra_module = THIS_MODULE,
				.cra_type = &crypto_ahash_type,
				.cra_init = sun8i_hash_crainit,
			}
		}
	}
},
{	.type = CRYPTO_ALG_TYPE_AHASH,
	.mode = CE_OP_SHA1,
	.ce_algo_id = CE_ID_HASH_SHA1,
	.hash_init = ce_sha1_init,
	.alg.hash = {
		.init = sun8i_hash_init,
		.update = sun8i_hash_update,
		.final = sun8i_hash_final,
		.finup = sun8i_hash_finup,
		.digest = sun8i_hash_digest,
		.export = sun8i_hash_export_sha1,
		.import = sun8i_hash_import_sha1,
		.halg = {
			.digestsize = SHA1_DIGEST_SIZE,
			.statesize = sizeof(struct sha1_state),
			.base = {
				.cra_name = "sha1",
				.cra_driver_name = "sha1-sun8i-ss",
				.cra_priority = 300,
				.cra_alignmask = 3,
				.cra_flags = CRYPTO_ALG_TYPE_AHASH |
					CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_NEED_FALLBACK,
				.cra_blocksize = SHA1_BLOCK_SIZE,
				.cra_ctxsize = sizeof(struct sun8i_hash_reqctx),
				.cra_module = THIS_MODULE,
				.cra_type = &crypto_ahash_type,
				.cra_init = sun8i_hash_crainit
			}
		}
	}
},
{	.type = CRYPTO_ALG_TYPE_AHASH,
	.mode = CE_OP_SHA224,
	.ce_algo_id = CE_ID_HASH_SHA224,
	.hash_init = ce_sha224_init,
	.alg.hash = {
		.init = sun8i_hash_init,
		.update = sun8i_hash_update,
		.final = sun8i_hash_final,
		.finup = sun8i_hash_finup,
		.digest = sun8i_hash_digest,
		.export = sun8i_hash_export_sha256,
		.import = sun8i_hash_import_sha256,
		.halg = {
			.digestsize = SHA224_DIGEST_SIZE,
			.statesize = sizeof(struct sha256_state),
			.base = {
				.cra_name = "sha224",
				.cra_driver_name = "sha224-sun8i-ss",
				.cra_priority = 300,
				.cra_alignmask = 3,
				.cra_flags = CRYPTO_ALG_TYPE_AHASH |
					CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_NEED_FALLBACK,
				.cra_blocksize = SHA224_BLOCK_SIZE,
				.cra_ctxsize = sizeof(struct sun8i_hash_reqctx),
				.cra_module = THIS_MODULE,
				.cra_type = &crypto_ahash_type,
				.cra_init = sun8i_hash_crainit
			}
		}
	}
},
{	.type = CRYPTO_ALG_TYPE_AHASH,
	.mode = CE_OP_SHA256,
	.ce_algo_id = CE_ID_HASH_SHA256,
	.hash_init = ce_sha256_init,
	.alg.hash = {
		.init = sun8i_hash_init,
		.update = sun8i_hash_update,
		.final = sun8i_hash_final,
		.finup = sun8i_hash_finup,
		.digest = sun8i_hash_digest,
		.export = sun8i_hash_export_sha256,
		.import = sun8i_hash_import_sha256,
		.halg = {
			.digestsize = SHA256_DIGEST_SIZE,
			.statesize = sizeof(struct sha256_state),
			.base = {
				.cra_name = "sha256",
				.cra_driver_name = "sha256-sun8i-ss",
				.cra_priority = 300,
				.cra_alignmask = 3,
				.cra_flags = CRYPTO_ALG_TYPE_AHASH |
					CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_NEED_FALLBACK,
				.cra_blocksize = SHA256_BLOCK_SIZE,
				.cra_ctxsize = sizeof(struct sun8i_hash_reqctx),
				.cra_module = THIS_MODULE,
				.cra_type = &crypto_ahash_type,
				.cra_init = sun8i_hash_crainit
			}
		}
	}
},
{	.type = CRYPTO_ALG_TYPE_AHASH,
	.mode = CE_OP_SHA384,
	.ce_algo_id = CE_ID_HASH_SHA384,
	.hash_init = ce_sha384_init,
	.alg.hash = {
		.init = sun8i_hash_init,
		.update = sun8i_hash_update,
		.final = sun8i_hash_final,
		.finup = sun8i_hash_finup,
		.digest = sun8i_hash_digest,
		.export = sun8i_hash_export_sha512,
		.import = sun8i_hash_import_sha512,
		.halg = {
			.digestsize = SHA384_DIGEST_SIZE,
			.statesize = sizeof(struct sha512_state),
			.base = {
				.cra_name = "sha384",
				.cra_driver_name = "sha384-sun8i-ss",
				.cra_priority = 300,
				.cra_alignmask = 3,
				.cra_flags = CRYPTO_ALG_TYPE_AHASH |
					CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_NEED_FALLBACK,
				.cra_blocksize = SHA384_BLOCK_SIZE,
				.cra_ctxsize = sizeof(struct sun8i_hash_reqctx),
				.cra_module = THIS_MODULE,
				.cra_type = &crypto_ahash_type,
				.cra_init = sun8i_hash_crainit
			}
		}
	}
},
{	.type = CRYPTO_ALG_TYPE_AHASH,
	.mode = CE_OP_SHA512,
	.ce_algo_id = CE_ID_HASH_SHA512,
	.hash_init = ce_sha512_init,
	.alg.hash = {
		.init = sun8i_hash_init,
		.update = sun8i_hash_update,
		.final = sun8i_hash_final,
		.finup = sun8i_hash_finup,
		.digest = sun8i_hash_digest,
		.export = sun8i_hash_export_sha512,
		.import = sun8i_hash_import_sha512,
		.halg = {
			.digestsize = SHA512_DIGEST_SIZE,
			.statesize = sizeof(struct sha512_state),
			.base = {
				.cra_name = "sha512",
				.cra_driver_name = "sha512-sun8i-ss",
				.cra_priority = 300,
				.cra_alignmask = 3,
				.cra_flags = CRYPTO_ALG_TYPE_AHASH |
					CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_NEED_FALLBACK,
				.cra_blocksize = SHA512_BLOCK_SIZE,
				.cra_ctxsize = sizeof(struct sun8i_hash_reqctx),
				.cra_module = THIS_MODULE,
				.cra_type = &crypto_ahash_type,
				.cra_init = sun8i_hash_crainit
			}
		}
	}
},
#ifdef CONFIG_CRYPTO_DEV_SUN8I_SS_RSA
{
	.type = CRYPTO_ALG_TYPE_AKCIPHER,
	.alg.rsa = {
		.encrypt = sun8i_rsa_encrypt,
		.decrypt = sun8i_rsa_decrypt,
		.sign = sun8i_rsa_sign,
		.verify = sun8i_rsa_verify,
		.set_priv_key = sun8i_rsa_set_priv_key,
		.set_pub_key = sun8i_rsa_set_pub_key,
		.max_size = sun8i_rsa_max_size,
			.init = sun8i_rsa_init,
			.exit = sun8i_rsa_exit,
		.base = {
			.cra_name = "rsa",
			.cra_driver_name = "rsa-sun8i-ce",
			.cra_priority = 300,
			.cra_flags = CRYPTO_ALG_TYPE_AKCIPHER |
				CRYPTO_ALG_ASYNC | CRYPTO_ALG_NEED_FALLBACK,
			.cra_ctxsize = sizeof(struct sun8i_tfm_rsa_ctx),
			.cra_module = THIS_MODULE,
			.cra_alignmask = 3,
		}
	}
}
#endif
};

static int sun8i_ss_probe(struct platform_device *pdev)
{
	struct resource *res;
	u32 v;
	int err, i, ce_method;
	struct sun8i_ss_ctx *ss;

	if (!pdev->dev.of_node)
		return -ENODEV;

	ss = devm_kzalloc(&pdev->dev, sizeof(*ss), GFP_KERNEL);
	if (!ss)
		return -ENOMEM;

	ss->variant = of_device_get_match_data(&pdev->dev);
	if (!ss->variant) {
		dev_err(&pdev->dev, "Missing Crypto Engine variant\n");
		return -EINVAL;
	}

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	ss->base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(ss->base)) {
		err = PTR_ERR(ss->base);
		dev_err(&pdev->dev, "Cannot request MMIO %d\n", err);
		return err;
	}

	ss->busclk = devm_clk_get(&pdev->dev, "ahb1_ce");
	if (IS_ERR(ss->busclk)) {
		err = PTR_ERR(ss->busclk);
		dev_err(&pdev->dev, "Cannot get AHB SS clock err=%d\n", err);
		return err;
	}
	dev_dbg(&pdev->dev, "clock ahb_ss acquired\n");

	ss->ssclk = devm_clk_get(&pdev->dev, "mod");
	if (IS_ERR(ss->ssclk)) {
		err = PTR_ERR(ss->ssclk);
		dev_err(&pdev->dev, "Cannot get SS clock err=%d\n", err);
		return err;
	}

	ss->reset = devm_reset_control_get_optional(&pdev->dev, "ahb");
	if (IS_ERR(ss->reset)) {
		if (PTR_ERR(ss->reset) == -EPROBE_DEFER)
			return PTR_ERR(ss->reset);
		dev_info(&pdev->dev, "no reset control found\n");
		ss->reset = NULL;
	}

	/* Enable both clocks */
	err = clk_prepare_enable(ss->busclk);
	if (err != 0) {
		dev_err(&pdev->dev, "Cannot prepare_enable busclk\n");
		return err;
	}

	err = clk_prepare_enable(ss->ssclk);
	if (err != 0) {
		dev_err(&pdev->dev, "Cannot prepare_enable ssclk\n");
		goto error_clk;
	}
	/* Deassert reset if we have a reset control */
	if (ss->reset) {
		err = reset_control_deassert(ss->reset);
		if (err) {
			dev_err(&pdev->dev, "Cannot deassert reset control\n");
			goto error_ssclk;
		}
	}

	ss->nsbase = ioremap(0x01c15800, 0x40);
	if (ss->nsbase) {
		v = readl(ss->nsbase + CE_CTR);
		v &= 0x07;
		dev_info(&pdev->dev, "CE_S Die ID %x\n", v);
	}
	iounmap(ss->nsbase);
	/*
	ss->nsbase = ioremap(0x01ce000, 0x40);
	v = BIT(15);
	writel(v, ss->nsbase + 0x0C);
	for (i = 0; i < 0x40; i += 4) {
		v  = readl(ss->nsbase + i);
		dev_info(&pdev->dev, "SMC_%x %x\n", i, v);
	}
	iounmap(ss->nsbase);
	ss->nsbase = ioremap(0x01c23400, 0x40);
	for (i = 0; i < 0x24; i += 4) {
		v  = readl(ss->nsbase + i);
		dev_info(&pdev->dev, "SMTA_%x %x\n", i, v);
	}
	iounmap(ss->nsbase);
	ss->nsbase = ioremap(0x01F01400, 0x1FF);
	writel(1, ss->nsbase + 0x1F4);
	for (i = 0; i < 0x1FF; i += 4) {
		v  = readl(ss->nsbase + i);
		dev_info(&pdev->dev, "R_PCRM_%x %x\n", i, v);
	}
	iounmap(ss->nsbase);
	*/
	v = readl(ss->base + CE_CTR);
	v >>= 16;
	v &= 0x07;
	dev_info(&pdev->dev, "CE_NS Die ID %x\n", v);

	ss->dev = &pdev->dev;
	platform_set_drvdata(pdev, ss);

	mutex_init(&ss->mlock);

	for (i = 0; i < MAXCHAN; i++) {
		init_completion(&ss->chanlist[i].complete);
		mutex_init(&ss->chanlock[i]);

		ss->engines[i] = crypto_engine_alloc_init(ss->dev, 1);
		if (!ss->engines[i]) {
			dev_err(ss->dev, "Cannot request engine\n");
			goto error_engine;
		}
		ss->engines[i]->cipher_one_request = handle_cipher_request;
		ss->engines[i]->hash_one_request = handle_hash_request;
		err = crypto_engine_start(ss->engines[i]);
		if (err) {
			dev_err(ss->dev, "Cannot request engine\n");
			goto error_engine;
		}
	}
	/* Get Secure IRQ */
	ss->irq = platform_get_irq(pdev, 0);
	if (ss->irq < 0) {
		dev_err(ss->dev, "Cannot get S IRQ\n");
		goto error_clk;
	}

	err = devm_request_irq(&pdev->dev, ss->irq, ce_irq_handler, 0,
			       "sun8i-ce-s", ss);
	if (err < 0) {
		dev_err(ss->dev, "Cannot request S IRQ\n");
		goto error_clk;
	}

	/* Get Non Secure IRQ */
	ss->ns_irq = platform_get_irq(pdev, 1);
	if (ss->ns_irq < 0) {
		dev_err(ss->dev, "Cannot get NS IRQ\n");
		goto error_clk;
	}

	err = devm_request_irq(&pdev->dev, ss->ns_irq, ce_irq_handler, 0,
			       "sun8i-ce-ns", ss);
	if (err < 0) {
		dev_err(ss->dev, "Cannot request NS IRQ\n");
		goto error_clk;
	}

	for (i = 0; i < MAXCHAN; i++) {
		ss->tl[i] = dma_alloc_coherent(ss->dev, sizeof(struct ss_task),
					       &ss->ce_t_phy[i], GFP_KERNEL);
		if (!ss->tl[i]) {
			dev_err(ss->dev, "Cannot get DMA memory for task %d\n",
				i);
			err = -EINVAL;
			return err;
		}
	}

	for (i = 0; i < ARRAY_SIZE(ss_algs); i++) {
		ss_algs[i].ss = ss;
		switch (ss_algs[i].type) {
		case CRYPTO_ALG_TYPE_ABLKCIPHER:
			err = crypto_register_alg(&ss_algs[i].alg.crypto);
			if (err != 0) {
				dev_err(ss->dev, "Fail to register %s\n",
					ss_algs[i].alg.crypto.cra_name);
				goto error_alg;
			}
			break;
		case CRYPTO_ALG_TYPE_AKCIPHER:
			err = crypto_register_akcipher(&ss_algs[i].alg.rsa);
			if (err != 0) {
				dev_err(ss->dev, "Fail to register RSA %s\n",
					ss_algs[i].alg.rsa.base.cra_name);
				goto error_alg;
			}
			break;
		case CRYPTO_ALG_TYPE_AHASH:
			err = ss->variant->alg_hash[ss_algs[i].ce_algo_id];
			if (err == CE_ID_NOTSUPP)
				break;
			err = crypto_register_ahash(&ss_algs[i].alg.hash);
			if (err != 0) {
				dev_err(ss->dev, "Fail to register %s\n",
					ss_algs[i].alg.hash.halg.base.cra_name);
				goto error_alg;
			}
			break;
		}
	}

	ce_method = ss->variant->prng;
	if (ce_method != CE_ID_NOTSUPP)
		sun8i_ce_hwrng_register(&ss->prng, "Sun8i-ce PRNG",
					PRNG_SEED_SIZE, PRNG_DATA_SIZE,
					ce_method, ss);

	ce_method = ss->variant->trng;
	if (ce_method != CE_ID_NOTSUPP)
		sun8i_ce_hwrng_register(&ss->trng, "Sun8i-ce TRNG", 0,
					TRNG_DATA_SIZE, ce_method, ss);

	return 0;
error_alg:
	i--;
	for (; i >= 0; i--) {
		switch (ss_algs[i].type) {
		case CRYPTO_ALG_TYPE_ABLKCIPHER:
			crypto_unregister_alg(&ss_algs[i].alg.crypto);
			break;
		case CRYPTO_ALG_TYPE_AHASH:
			err = ss->variant->alg_hash[ss_algs[i].ce_algo_id];
			if (err == CE_ID_NOTSUPP)
				break;
			crypto_unregister_ahash(&ss_algs[i].alg.hash);
			break;
		case CRYPTO_ALG_TYPE_AKCIPHER:
			crypto_unregister_akcipher(&ss_algs[i].alg.rsa);
			break;
		}
	}
	if (ss->reset)
		reset_control_assert(ss->reset);
error_engine:
	while (i >= 0) {
		crypto_engine_exit(ss->engines[i]);
		i--;
	}
error_clk:
	clk_disable_unprepare(ss->ssclk);
error_ssclk:
	clk_disable_unprepare(ss->busclk);
	return err;
}

static int sun8i_ss_remove(struct platform_device *pdev)
{
	int i, timeout, id;
	struct sun8i_ss_ctx *ss = platform_get_drvdata(pdev);

	sun8i_ce_hwrng_unregister(&ss->prng.hwrng);
	/*sun8i_ce_hwrng_unregister(&ss->trng.hwrng);*/

	for (i = 0; i < ARRAY_SIZE(ss_algs); i++) {
		switch (ss_algs[i].type) {
		case CRYPTO_ALG_TYPE_ABLKCIPHER:
			crypto_unregister_alg(&ss_algs[i].alg.crypto);
			break;
		case CRYPTO_ALG_TYPE_AHASH:
			id = ss_algs[i].ce_algo_id;
			if (ss->variant->alg_hash[id] == CE_ID_NOTSUPP)
				break;
			crypto_unregister_ahash(&ss_algs[i].alg.hash);
			break;
		case CRYPTO_ALG_TYPE_AKCIPHER:
			crypto_unregister_akcipher(&ss_algs[i].alg.rsa);
			break;
		}
	}
	for (i = 0; i < MAXCHAN; i++) {
		crypto_engine_exit(ss->engines[i]);
		timeout = 0;
		while (mutex_is_locked(&ss->chanlock[i]) && timeout < 10) {
			dev_info(ss->dev, "Wait for %d %d\n", i, timeout);
			timeout++;
			msleep(20);
		}
	}

	/* TODO check that any request are still under work */

	if (ss->reset)
		reset_control_assert(ss->reset);
	clk_disable_unprepare(ss->busclk);
	return 0;
}

static const struct of_device_id h3_ss_crypto_of_match_table[] = {
	{ .compatible = "allwinner,sun8i-h3-crypto",
	  .data = &ce_h3_variant },
	{ .compatible = "allwinner,sun50i-a64-crypto",
	  .data = &ce_a64_variant },
	{ .compatible = "allwinner,sun8i-a83t-crypto",
	  .data = &ce_a83t_variant },
	{}
};
MODULE_DEVICE_TABLE(of, h3_ss_crypto_of_match_table);

static struct platform_driver sun8i_ss_driver = {
	.probe		  = sun8i_ss_probe,
	.remove		 = sun8i_ss_remove,
	.driver		 = {
		.name		   = "sun8i-ss",
		.of_match_table	= h3_ss_crypto_of_match_table,
	},
};

module_platform_driver(sun8i_ss_driver);

MODULE_DESCRIPTION("Allwinner Security System cryptographic accelerator");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Corentin Labbe <clabbe.montjoie@gmail.com>");
