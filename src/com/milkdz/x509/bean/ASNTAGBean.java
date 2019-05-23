package com.milkdz.x509.bean;

/**
 * Created by MilkZS on 2019/3/1 15:00
 */
public class ASNTAGBean {

    public static final int MAX_LEN = 8192;
    public static final int SIMPLE = 0;     //简单编码
    public static final int STRUCT = 1;      //结构化编码
    /**
     * 简单类型
     * <p>
     * BIT STRING:由0和1任意组成的比特流
     * IA5String:由IA5(ASCII)字符任意组成的字符流
     * INTEGER:一个任意的整数
     * NULL:null值
     * OBJECT IDENTIFIER:对象标识符，有一列整数构成，用于确定对象，如算法或属性类型
     * OCTET STRING:任意的octet（8 bit值）流
     * PrintableString:任意可打印字符流
     * T61String:T.61（8bit）字符的任意流
     * UTCTime:"coordinated universal time"或者格林威治平均时（GMT）值。
     */
    public static final int TAG_ASN_BOOLEAN = 1;
    public static final int TAG_ASN_INTEGER = 2;
    public static final int TAG_ASN_BIT_STRING = 3;
    public static final int TAG_ASN_OCTET_STRING = 4;
    public static final int TAG_ASN_NULL = 5;
    public static final int TAG_ASN_OBJECT_IDENTIFIER = 6;
    public static final int TAG_ASN_PrintableString = 19;
    public static final int TAG_ASN_T61String = 20;
    public static final int TAG_ASN_IA5String = 22;
    public static final int TAG_ASN_UTCTime = 23;


    /**
     * 结构类型
     */
    public static final int TAG_ASN_SEQUENCE_AND_SEQUENCE_OF = 16;
    public static final int TAG_ASN_SET_AND_SET_OF = 17;

    public final static int rsaEncrypt = 0;
    public final static int sha1Rsa = 1;
    public final static int md2Rsa = 2;
    public final static int md4Rsa = 3;
    public final static int md5Rsa = 4;
    public final static int sm3sm2 = 5;
    public final static int sha256Rsa = 6;
    public final static int sha384Rsa = 7;
    public final static int sha512Rsa = 8;
    public final static int ecEncrypt = 9;
    public final static int ecPublicKey = 10;
}
