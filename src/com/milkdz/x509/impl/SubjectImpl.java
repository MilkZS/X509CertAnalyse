package com.milkdz.x509.impl;

import com.milkdz.x509.bean.Subject;
import com.milkdz.x509.tlv.ZTLVBase;
import com.milkdz.x509.tlv.ZTLVContain;
import com.milkdz.x509.util.ByteArrayBuffer;

/**
 * Created by zuoqi@bhz.com.cn on 2019/5/29 16:06
 */
public class SubjectImpl {

    private Subject subject;

    public SubjectImpl() {
        this.subject = new Subject();
    }

    public boolean parse(ByteArrayBuffer buffer) {
        try {

            ZTLVBase head = new ZTLVBase();
            head.parse(buffer);
            // 获取SEQUENCE
            ZTLVContain container1 = new ZTLVContain();
            container1.parse(head.getValue());
            for (int i = 0; i < container1.itemCount(); i++) {
                // 获取SET
                ZTLVBase base = container1.getItem(i);
                // 获取SEQUENCE
                ZTLVBase baseSE = new ZTLVBase();
                baseSE.parse(base.getValue());
                ZTLVContain container3 = new ZTLVContain();
                container3.parse(baseSE.getValue());

                ZTLVBase bValue = container3.getItem(1);
                byte[] bValu = bValue.getValue().buffer();
                int j = 0;
                for (; j < bValu.length; j++) {
                    if (bValu[j] == 0x00) {
                        break;
                    }
                }
                byte[] newB = new byte[j];
                System.arraycopy(bValu, 0, newB, 0, newB.length);
                String value = new String(newB);

                ZTLVBase bTAG = container3.getItem(0);
                byte[] bArr = bTAG.getValue().buffer();
                switch (bArr[2]){
                    case 3:{
                        this.subject.setSubject(value);
                        this.subject.setCommonName(value);
                    }break;
                    case 11:{
                        this.subject.setOrganizationalUnitName(value);
                    }break;
                    case 10:{
                        this.subject.setOrganizationName(value);
                    }break;
                    case 6:{
                        this.subject.setCountryName(value);
                    }break;
                }
            }
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public Subject getSubject() {
        return subject;
    }
}
