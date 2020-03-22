// SPDX-License-Identifier: GPL-2.0-only

#include "netlink.h"
#include "common.h"
#include "bitset.h"

struct fec_req_info {
	struct ethnl_req_info		base;
};

struct fec_reply_data {
	struct ethnl_reply_data		base;
	struct ethtool_fecparam		fec;
};

#define FEC_REPDATA(__reply_base) \
	container_of(__reply_base, struct fec_reply_data, base)

static const struct nla_policy
fec_get_policy[ETHTOOL_A_FEC_MAX + 1] = {
	[ETHTOOL_A_FEC_UNSPEC]		= { .type = NLA_REJECT },
	[ETHTOOL_A_FEC_HEADER]		= { .type = NLA_NESTED },
	[ETHTOOL_A_FEC_MODES]		= { .type = NLA_REJECT },
};

static int fec_prepare_data(const struct ethnl_req_info *req_base,
				 struct ethnl_reply_data *reply_base,
				 struct genl_info *info)
{
	struct fec_reply_data *data = FEC_REPDATA(reply_base);
	struct net_device *dev = reply_base->dev;
	int ret;

	if (!dev->ethtool_ops->get_fecparam)
		return -EOPNOTSUPP;
	ret = ethnl_ops_begin(dev);
	if (ret < 0)
		return ret;
	ret = dev->ethtool_ops->get_fecparam(dev, &data->fec);
	ethnl_ops_complete(dev);

	return ret;
}

static int fec_reply_size(const struct ethnl_req_info *req_base,
			       const struct ethnl_reply_data *reply_base)
{
	bool compact = req_base->flags & ETHTOOL_FLAG_COMPACT_BITSETS;
	const struct fec_reply_data *data = FEC_REPDATA(reply_base);

	return ethnl_bitset32_size(&data->fec.active_fec, &data->fec.fec,
				   ETHTOOL_FEC_MODE_COUNT, fec_mode_names,
				   compact);
}

static int fec_fill_reply(struct sk_buff *skb,
			       const struct ethnl_req_info *req_base,
			       const struct ethnl_reply_data *reply_base)
{
	bool compact = req_base->flags & ETHTOOL_FLAG_COMPACT_BITSETS;
	const struct fec_reply_data *data = FEC_REPDATA(reply_base);

	return ethnl_put_bitset32(skb, ETHTOOL_A_FEC_MODES,
				  &data->fec.active_fec, &data->fec.fec,
				  ETHTOOL_FEC_MODE_COUNT, fec_mode_names,
				  compact);
}

const struct ethnl_request_ops ethnl_fec_request_ops = {
	.request_cmd		= ETHTOOL_MSG_FEC_GET,
	.reply_cmd		= ETHTOOL_MSG_FEC_GET_REPLY,
	.hdr_attr		= ETHTOOL_A_FEC_HEADER,
	.max_attr		= ETHTOOL_A_FEC_MAX,
	.req_info_size		= sizeof(struct fec_req_info),
	.reply_data_size	= sizeof(struct fec_reply_data),
	.request_policy		= fec_get_policy,

	.prepare_data		= fec_prepare_data,
	.reply_size		= fec_reply_size,
	.fill_reply		= fec_fill_reply,
};

/* FEC_SET */

static const struct nla_policy
fec_set_policy[ETHTOOL_A_FEC_MAX + 1] = {
	[ETHTOOL_A_FEC_UNSPEC]		= { .type = NLA_REJECT },
	[ETHTOOL_A_FEC_HEADER]		= { .type = NLA_NESTED },
	[ETHTOOL_A_FEC_MODES]		= { .type = NLA_NESTED },
};

int ethnl_set_fec(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *tb[ETHTOOL_A_FEC_MAX + 1];
	struct ethtool_fecparam fec = {};
	struct ethnl_req_info req_info = {};
	const struct ethtool_ops *ops;
	struct net_device *dev;
	bool mod = false;
	int ret;

	ret = nlmsg_parse(info->nlhdr, GENL_HDRLEN, tb, ETHTOOL_A_FEC_MAX,
			  fec_set_policy, info->extack);
	if (ret < 0)
		return ret;
	ret = ethnl_parse_header_dev_get(&req_info, tb[ETHTOOL_A_FEC_HEADER],
					 genl_info_net(info), info->extack,
					 true);
	if (ret < 0)
		return ret;
	dev = req_info.dev;
	ops = dev->ethtool_ops;
	ret = -EOPNOTSUPP;
	if (!ops->get_fecparam || !ops->set_fecparam)
		goto out_dev;

	rtnl_lock();
	ret = ethnl_ops_begin(dev);
	if (ret < 0)
		goto out_rtnl;
	ret = ops->get_fecparam(dev, &fec);
	if (ret < 0)
		goto out_ops;

	ret = ethnl_update_bitset32(&fec.fec, ETHTOOL_FEC_MODE_COUNT,
				    tb[ETHTOOL_A_FEC_MODES], fec_mode_names,
				    info->extack, &mod);
	if (ret < 0 || !mod)
		goto out_ops;

	ret = dev->ethtool_ops->set_fecparam(dev, &fec);
	if (ret < 0)
		goto out_ops;
	ethtool_notify(dev, ETHTOOL_MSG_FEC_NTF, NULL);

out_ops:
	ethnl_ops_complete(dev);
out_rtnl:
	rtnl_unlock();
out_dev:
	dev_put(dev);
	return ret;
}
