package com.milkdz.x509.tlv;

import com.milkdz.x509.bean.ASNTAGBean;
import com.milkdz.x509.util.ByteArrayBuffer;

/**
 * Created by MilkZS on 2019/5/23 10:15
 */
public class ZTLVInteger extends ZTLVItem {
    public ZTLVInteger() {
        super(ASNTAGBean.TAG_ASN_INTEGER);
    }

    public int checkIntegerBytes(int value) {
        //若value为0时,占用一个字节
        if (value == 0) return 1;

        //检查value由几个字节组成
        int len = 0;
        for (len = 0; value > 0; ++len) {
            value >>= 8;
        }
        return len;
    }

    public void setValue(int value) {
        int len = checkIntegerBytes(value);
        byte bValue[] = new byte[len];
        for (int i = 0; i < len; i++) {
            bValue[i] = (byte) (value >> 8 * i);
        }
        ByteArrayBuffer data = new ByteArrayBuffer(len);
        data.append(bValue, 0, len);
        super.setValue(data);
    }

    @Override
    public void setValue(byte[] value) {
        ByteArrayBuffer data;
        //如果第一个BYTE的数值大于0x80，就在前面加0x00（第一个bit是符号位。02 01 80表示的是-127, 而02 02 00 80表示128）
        byte firstByte = value[0];
        if ((0x000000ff & firstByte) >= 0x80) {
            data = new ByteArrayBuffer(1 + value.length);
            data.append(0);
        } else {
            data = new ByteArrayBuffer(value.length);
        }
        data.append(value, 0, value.length);
        super.setValue(data);
    }

    public void setValue(ByteArrayBuffer value) {
        ByteArrayBuffer data;
        byte[] zero = new byte[1];
        zero[0] = 0x00;

        //如果第一个BYTE的数值大于0x80，就在前面加0x00（第一个bit是符号位。02 01 80表示的是-127, 而02 02 00 80表示128）
        byte firstByte = value.buffer()[0];
        if ((0x000000ff & firstByte) >= 0x80) {
            data = new ByteArrayBuffer(1 + value.length());
            data.append(zero, 0, 1);
        } else {
            data = new ByteArrayBuffer(value.length());
        }
        data.append(value.buffer(), 0, value.length());
        super.setValue(data);
    }

    public boolean parse(ZTLVBase item) {
        if (item.getTag() != ASNTAGBean.TAG_ASN_INTEGER) return false;
        return super.parse(item);
    }
}
