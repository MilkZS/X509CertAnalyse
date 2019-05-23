package com.milkdz.x509.tlv;

import com.milkdz.x509.util.ByteArrayBuffer;

/**
 * Created by MilkZS on 2019/5/23 10:13
 */
public class ZTLVAttribute extends ZTLVItem {
    public ZTLVAttribute() {
        super(0);
    }

    public ZTLVAttribute(int type) {
        super(0xa0 + type);
    }

    public boolean parse(ZTLVBase item) {
        int tag = item.getTag();

        //此处可能有隐患，因为TAG从0到3有其他的可能行，不一定是属性A0-A3
        if (tag > 3) return false;
        return super.parse(item);
    }

    public ByteArrayBuffer make() {
        int tag = getTag();

        ZTLVBase item = new ZTLVBase();
        item.setTag(tag - 0xa0);
        item.setValue(getValue());
        ByteArrayBuffer der = item.getEncodingData();
        (der.buffer())[0] += 0xa0;
        return der;
    }
}
