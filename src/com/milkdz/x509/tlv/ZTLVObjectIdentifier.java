package com.milkdz.x509.tlv;

import com.milkdz.x509.bean.ASNTAGBean;

/**
 * Created by MilkZS on 2019/5/23 10:09
 */
public class ZTLVObjectIdentifier extends ZTLVItem {
    public ZTLVObjectIdentifier() {
        super(ASNTAGBean.TAG_ASN_OBJECT_IDENTIFIER);
    }

    public boolean parse(ZTLVBase item) {
        if (item.getTag() != ASNTAGBean.TAG_ASN_OBJECT_IDENTIFIER) return false;
        return super.parse(item);
    }
}
