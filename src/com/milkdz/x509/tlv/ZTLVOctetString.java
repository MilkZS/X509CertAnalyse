package com.milkdz.x509.tlv;

import com.milkdz.x509.bean.ASNTAGBean;
import com.milkdz.x509.util.ByteArrayBuffer;

/**
 * Created by MilkZS on 2019/5/23 10:10
 */
public class ZTLVOctetString extends ZTLVItem {
    public ZTLVOctetString() {
        super(ASNTAGBean.TAG_ASN_OCTET_STRING);
    }

    public boolean parse(ZTLVBase item) {
        if (item.getTag() != ASNTAGBean.TAG_ASN_OCTET_STRING) return false;
        return super.parse(item);
    }

    public ByteArrayBuffer make(ByteArrayBuffer octerStr) {
        if (octerStr.isEmpty()) return null;
        return getEncodingData();
    }
}
