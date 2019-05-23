package com.milkdz.x509.bean;

import com.milkdz.x509.tlv.ZTLVBase;
import com.milkdz.x509.tlv.ZTLVItem;

/**
 * Created by MilkZS on 2019/5/23 9:07
 */
public class ASNInteger extends ZTLVItem {

    public ASNInteger() {
        super(ASNTAGBean.TAG_ASN_INTEGER);
    }

    public boolean parse(ZTLVBase item) {
        if (item.getTag() != ASNTAGBean.TAG_ASN_INTEGER) return false;
        return super.parse(item);
    }

    private int checkIntegerBytes(int value) {
        //若value为0时,占用一个字节
        if (value == 0) return 1;

        //检查value由几个字节组成
        int len = 0;
        for (len = 0; value > 0; ++len) {
            value >>= 8;
        }
        return len;
    }


}
