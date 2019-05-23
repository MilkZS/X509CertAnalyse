package com.milkdz.x509.bean;

import com.milkdz.x509.tlv.ZTLVBase;
import com.milkdz.x509.tlv.ZTLVContain;

/**
 * Created by MilkZS on 2019/5/22 16:50
 */
public class ValidityTime {
    public ValidityTime() {
    }

    private String startTime;
    private String endTime;

    /*
    Validity ::= SEQUENCE {
        notBefore      Time,
        notAfter       Time }
    Time ::= CHOICE {
        utcTime        UTCTime,
        generalTime    GeneralizedTime }
    */
    public boolean parse(ZTLVBase item) {
        if (item.getTag() != ASNTAGBean.TAG_ASN_SEQUENCE_AND_SEQUENCE_OF) return false;

        ZTLVContain container = new ZTLVContain();
        if (!container.parse(item.getValue())) return false;
        if (container.itemCount() != 2) return false;

        ZTLVBase notBefore = container.getItem(0);
        ZTLVBase notAfter = container.getItem(1);
        startTime = new String(notBefore.getValue().buffer());
        endTime = new String(notAfter.getValue().buffer());
        return true;
    }

    public String getStartTime() {
        return parseTime(startTime);
    }

    public String getEndTime() {
        return parseTime(endTime);
    }

    private String parseTime(String time) {
        return "20" + time.substring(0, 2) + "/" + time.substring(2, 4) + "/" + time.substring(4, 6);
    }
}
