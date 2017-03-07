#include "sun8i-ss.h"

static int sun8i_ce_seed(struct sun8i_ce_hwrng *sch)
{
	sch->seed = kmalloc(sch->seedsize, GFP_KERNEL | GFP_DMA | GFP_ATOMIC);
	if (!sch->seed)
		return -ENOMEM;

	dev_info(sch->ss->dev, "%s\n", __func__);
	get_random_bytes(sch->seed, sch->seedsize);
	return 0;
}

static void sun8i_ce_schedule_async_seed(struct random_ready_callback *rdy)
{
	struct sun8i_ce_hwrng *sch;
	struct sun8i_ss_ctx *ss;

	sch = container_of(rdy, struct sun8i_ce_hwrng, random_ready);
	ss = sch->ss;

	dev_info(ss->dev, "%s\n", __func__);
	sun8i_ce_seed(sch);
}

static int sun8i_ce_hwrng_init(struct hwrng *hwrng)
{
	struct sun8i_ss_ctx *ss;
	struct sun8i_ce_hwrng *sch;
	int ret = 0;

	sch = container_of(hwrng, struct sun8i_ce_hwrng, hwrng);
	ss = sch->ss;
	dev_info(ss->dev, "%s\n", __func__);

	if (sch->seedsize > 0) {
		sch->random_ready.owner = THIS_MODULE;
		sch->random_ready.func = sun8i_ce_schedule_async_seed;

		ret = add_random_ready_callback(&sch->random_ready);
		dev_info(ss->dev, "%s rready=%d\n", __func__, ret);

		switch (ret) {
		case 0:
			break;
		case -EALREADY:
			/* Random pool is ready, seed now */
			ret = sun8i_ce_seed(sch);
			sch->random_ready.func = NULL;
			break;
		default:
			sch->random_ready.func = NULL;
		}
	}
	return ret;
}

static int sun8i_ce_hwrng_read(struct hwrng *hwrng, void *buf,
			       size_t max, bool wait)
{
	size_t len;
	int flow = 3, ret;
	struct ss_task *cet;
	struct sun8i_ss_ctx *ss;
	struct sun8i_ce_hwrng *sch;
	void *data;

	/* TODO get flow number */
	sch = container_of(hwrng, struct sun8i_ce_hwrng, hwrng);
	ss = sch->ss;

	if (sch->seedsize && !sch->seed) {
		dev_err(ss->dev, "Not seeded\n");
		return -EAGAIN;
	}
	data = kmalloc(sch->datasize, GFP_KERNEL | GFP_DMA);
	if (!data)
		return -ENOMEM;

	len = min_t(size_t, max, sch->datasize);

	/*pr_info("%s %u (%u %u)\n", sch->name, max, sch->seedsize, sch->datasize);*/

	mutex_lock(&ss->chanlock[flow]);

	cet = ss->tl[flow];
	memset(cet, 0, sizeof(struct ss_task));
	cet->t_id = flow;
	cet->t_common_ctl = sch->ce_op | BIT(31);
	cet->t_dlen = sch->datasize / 4;

	cet->t_dst[0].addr = dma_map_single(ss->dev, data, sch->datasize,
					    DMA_FROM_DEVICE);
	if (dma_mapping_error(ss->dev, cet->t_dst[0].addr)) {
		dev_err(ss->dev, "Cannot DMA MAP DST DATA\n");
		ret = -EFAULT;
		goto fail;
	}
	cet->t_dst[0].len = sch->datasize / 4;

	cet->t_key = cet->t_dst[0].addr;
	if (sch->seed) {
		cet->t_iv = dma_map_single(ss->dev, sch->seed, sch->seedsize,
					   DMA_TO_DEVICE);
		if (dma_mapping_error(ss->dev, cet->t_iv)) {
			dev_err(ss->dev, "Cannot DMA MAP SEED\n");
			ret = -EFAULT;
			goto ce_rng_iv_err;
		}
	}

	ret = sun8i_ce_run_task(ss, flow, sch->hwrng.name);

	if (sch->seed)
		dma_unmap_single(ss->dev, cet->t_iv, sch->seedsize,
				 DMA_TO_DEVICE);
ce_rng_iv_err:
	dma_unmap_single(ss->dev, cet->t_dst[0].addr, sch->datasize,
			 DMA_FROM_DEVICE);

fail:
	mutex_unlock(&ss->chanlock[flow]);
	if (!ret) {
		memcpy(buf, data, len);
		/*print_hex_dump(KERN_INFO, "RNG ", DUMP_PREFIX_NONE, 16, 1, data,
		       sch->datasize, false);*/
	}
	kzfree(data);
	if (ret)
		return ret;

	return len;
}

int sun8i_ce_hwrng_register(struct sun8i_ce_hwrng *h, const char *name,
			    unsigned int seedsize, unsigned int datasize,
			    u32 ce_op, struct sun8i_ss_ctx *ss)
{
	h->name = name;
	h->ce_op = ce_op;
	h->ss = ss;
	h->seedsize = seedsize;
	h->datasize = datasize;

	h->hwrng.name = name;
	h->hwrng.init = sun8i_ce_hwrng_init;
	h->hwrng.read = sun8i_ce_hwrng_read;
	h->hwrng.quality = 1000;

	dev_info(ss->dev, "Registered %s\n", name);

	return hwrng_register(&h->hwrng);
}

void sun8i_ce_hwrng_unregister(struct hwrng *hwrng)
{
	struct sun8i_ce_hwrng *sch;

	if (!hwrng)
		return;

	sch = container_of(hwrng, struct sun8i_ce_hwrng, hwrng);

	if (sch->seedsize && sch->random_ready.func)
		del_random_ready_callback(&sch->random_ready);

	kfree(sch->seed);

	hwrng_unregister(hwrng);
}
