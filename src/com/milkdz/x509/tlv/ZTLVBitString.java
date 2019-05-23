package com.milkdz.x509.tlv;

import com.milkdz.x509.bean.ASNTAGBean;
import com.milkdz.x509.util.ByteArrayBuffer;

/**
 * Created by MilkZS on 2019/5/23 10:17
 */
public class ZTLVBitString extends ZTLVItem {

    private byte m_unusedBits;

    public ZTLVBitString() {
        super(ASNTAGBean.TAG_ASN_BIT_STRING);
        m_unusedBits = 0x00;
    }

    public boolean setUnusedBits(byte count) {
        if (count > 8) return false;
        m_unusedBits = count;
        return true;
    }

    public byte getUnusedBits() {
        return m_unusedBits;
    }

    @Override
    public void setValue(ByteArrayBuffer value) {
        ByteArrayBuffer buffer = new ByteArrayBuffer(value.length() + 1);
        buffer.append(0x00);
        buffer.append(value.buffer(), 0, value.length());
        super.setValue(buffer);
    }

    @Override
    public void setValue(byte[] value) {
        ByteArrayBuffer buffer = new ByteArrayBuffer(value.length + 1);
        buffer.append(0x00);
        buffer.append(value, 0, value.length);
        super.setValue(buffer);
    }

    public boolean parse(ZTLVBase item) {
        if (item.getTag() != ASNTAGBean.TAG_ASN_BIT_STRING) return false;

        //BITSTRING的BODY至少要有2个字节，一个字节为未用bit数，最少一个字节为内容
        if (item.getLength() < 2) return false;

        ByteArrayBuffer value = item.getValue();

        //获取第一个字节，赋值给m_unusedBits
        if (!setUnusedBits(value.buffer()[0])) return false;

        return super.parse(item);
    }

    public ByteArrayBuffer make() {
        if (m_unusedBits > 8) return null;

        ByteArrayBuffer value = getValue();
        if (value.buffer()[0] != m_unusedBits) {
            ByteArrayBuffer temp = new ByteArrayBuffer(value.length() + 1);
            byte tempByte[] = new byte[1];
            tempByte[0] = m_unusedBits;
            temp.append(tempByte, 0, 1);
            temp.append(value.buffer(), 0, value.length());

            ZTLVBase item = new ZTLVBase();
            item.setTag(getTag());
            item.setValue(value);
            return item.getEncodingData();
        } else {
            return getEncodingData();
        }
    }
}
