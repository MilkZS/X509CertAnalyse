package com.milkdz.x509.tlv;

import com.milkdz.x509.util.ByteArrayBuffer;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by MilkZS on 2019/5/22 10:22
 */
public class ZTLVContain {

    private List<ZTLVBase> tlvBaseList;     //子TLV对象列表

    public ZTLVContain() {
        tlvBaseList = new ArrayList<>();
    }

    public void clear() {
        tlvBaseList.clear();
    }

    public boolean parse(ByteArrayBuffer data) {
        if (data.isEmpty()) return false;

        //防止重复使用同一个CAsn1ItemContainer对象，此处先清除
        clear();

        int ulCount = 0;
        int ulOffset = 0;
        ByteArrayBuffer tmp = new ByteArrayBuffer(data.capacity());
        tmp.append(data.buffer(), 0, data.length());

        ZTLVBase item = new ZTLVBase();
        //尝试解析字符串,获取子TLV个数
        ByteArrayBuffer bTemp = new ByteArrayBuffer(data.capacity());
        while (ZTLVBase.dump(tmp, item)) {
            ulCount++;

            //移除已经解析过的部分
            bTemp.clear();
            bTemp.append(tmp.buffer(), item.m_length + item.m_tlLength, tmp.length() - item.m_length - item.m_tlLength);
            tmp.clear();
            tmp.append(bTemp.buffer(), 0, bTemp.length());

            //累计偏移量
            ulOffset += item.m_tlLength + item.m_length;
            if (tmp.isEmpty()) break;
        }

        //验证是否正好由N个TLV结构组成，是否存在越界或者剩余数据
        if (ulOffset != data.length()) return false;

        //正式分配空间，分解TLV并存储到列表
        for (int i = 0; i < ulCount; i++) {
            tlvBaseList.add(new ZTLVBase());
        }
        tmp.clear();
        tmp.append(data.buffer(), 0, data.length());

        for (int i = 0; i < ulCount; ++i) {
            ZTLVBase tmpTLV = tlvBaseList.get(i);
            if (!ZTLVBase.dump(tmp,tmpTLV )) {
                tlvBaseList = null;
                return false;
            }
            bTemp.clear();
            bTemp.append(tmp.buffer(), tmpTLV.m_length + tmpTLV.m_tlLength, tmp.length() - tmpTLV.m_length - tmpTLV.m_tlLength);
            tmp.clear();
            tmp.append(bTemp.buffer(), 0, bTemp.length());
        }
        return true;
    }

    public int itemCount() {
        return tlvBaseList.size();
    }

    public ZTLVBase getItem(int ulIndex) {
        return tlvBaseList.get(ulIndex);
    }

    public void addItem(ZTLVBase item) {
        this.tlvBaseList.add(item);
    }
}
