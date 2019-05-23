package com.milkdz.x509.tlv;

import com.milkdz.x509.util.ByteArrayBuffer;

/**
 * Created by MilkZS on 2019/5/23 10:07
 */
public class ZTLVItem extends ZTLVBase{

        public ZTLVItem(int tag) {
            super(tag);
        }

        public boolean parse(ZTLVBase item) {
            setTag(item.getTag());
            setValue(item.getValue());
            super.parse(item.getEncodingData());
            return true;
        }

        public ByteArrayBuffer make() {
            return super.getEncodingData();
        }
}
