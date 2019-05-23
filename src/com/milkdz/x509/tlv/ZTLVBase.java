package com.milkdz.x509.tlv;

import com.milkdz.x509.bean.ASNTAGBean;
import com.milkdz.x509.util.ByteArrayBuffer;

/**
 * Created by MilkZS on 2019/5/22 9:25
 */
public class ZTLVBase {

    private static final int INT_MAX = 2147483647;   /* maximum (signed) int value */
    private int m_tag;                 //T
    int m_length;              //L
    int m_tlLength;            //T+L的字节长度
    private ByteArrayBuffer m_data;                //DER编码后的数据
    private int m_type;        //编码类型

    private ByteArrayBuffer DerEncoding(int tag, int length, byte[] value) {
        byte buffer[] = new byte[20];
        int index = 0;

        //设置TAG
        if (tag < 31) {
            if (tag == ASNTAGBean.TAG_ASN_SEQUENCE_AND_SEQUENCE_OF || tag == ASNTAGBean.TAG_ASN_SET_AND_SET_OF) {
                buffer[index++] = (byte) (tag | 0x20);
            } else {
                buffer[index++] = (byte) tag;
            }
        } else {
            //当TAG大于31时，引导八位位组的第8位和第7为表示类型，第6位表示是原始编码或者结构编码
            //第1-5为固定全为1，这里我们固定使用如下引导数组，以后若需细分，再行修改
            buffer[index++] = (byte) (0xC0 | 0x1F);

            //计算TAG包含几个八位位组
            int i = 0;
            int ttag = tag;
            for (i = 0, ttag = tag; ttag > 0; ++i) {
                ttag >>= 7;
            }

            int offset = i;
            ttag = tag;

            //TAG八位位组赋值
            while (i-- > 0) {
                buffer[i] = (byte) (ttag & 0x7f);
                if (i != (offset - 1)) {
                    buffer[i] |= 0x80;
                }
                ttag >>= 7;
            }
            index += offset;
        }

        //设置长度
        int llength = 0;
        if (length <= 0x7f) {
            buffer[index++] = (byte) length;
            llength = 1;
        } else {
            //检查m_length由几个字节组成
            int i = 0;
            int len = length;
            for (i = 0; len > 0; ++i) {
                len >>= 8;
            }

            //n个字节，首先加入0x8n
            buffer[index++] = (byte) (i | 0x80);

            int pos = i;
            len = length;

            //长度八位位组赋值，使用little-endian
            while (i-- > 0) {
                buffer[index + i] = (byte) (len & 0xFF);
                len >>= 8;
            }

            index += pos;
            llength = pos + 1;
        }

        //拷贝value
        m_tlLength = 1 + llength;

        ByteArrayBuffer outDer = new ByteArrayBuffer(m_tlLength + length);
        outDer.append(buffer, 0, m_tlLength);
        outDer.append(value, 0, length);

        return outDer;
    }

    public ZTLVBase() {
        m_tag = 0;
        m_length = 0;
        m_tlLength = 0;
        m_data = new ByteArrayBuffer(ASNTAGBean.MAX_LEN);
        m_type = ASNTAGBean.SIMPLE;
    }

    public ZTLVBase(int tag) {
        m_length = 0;
        m_tlLength = 0;
        m_data = new ByteArrayBuffer(ASNTAGBean.MAX_LEN);
        setTag(tag);
    }


    public ZTLVBase(ZTLVBase other) {
        if (other == null) return;
        setTag(other.m_tag);
        m_length = other.m_length;
        m_tlLength = other.m_tlLength;
        m_data = new ByteArrayBuffer(other.m_length + other.m_tlLength);
        m_data.append(other.m_data.buffer(), 0, other.m_data.length());
    }

    public boolean isStructEncodeTag(int tag) {
        switch (tag) {
            case ASNTAGBean.TAG_ASN_SEQUENCE_AND_SEQUENCE_OF:
            case ASNTAGBean.TAG_ASN_SET_AND_SET_OF:
                return true;
            default:
                return false;
        }
    }

    public void setValue(byte[] value) {
        if (value != null) {
            m_length = value.length;
            m_data = DerEncoding(m_tag, value.length, value);
        }
    }

    public void setValue(ByteArrayBuffer value) {
        if (value != null) {
            m_length = value.length();
            m_data = DerEncoding(m_tag, value.length(), value.buffer());
        }
    }

    public boolean appendValue(ByteArrayBuffer value) {
        if (value == null) return false;
        ByteArrayBuffer oldValue = getValue();
        if (oldValue == null)
            oldValue = new ByteArrayBuffer(ASNTAGBean.MAX_LEN);
        oldValue.append(value.buffer(), 0, value.length());
        m_length = m_length + value.length();
        m_data = DerEncoding(m_tag, oldValue.length(), oldValue.buffer());
        return true;
    }

    public int getObjectLength(int tag, int valueLen) {
        int encodingDataLen = valueLen;
        encodingDataLen++; //加上默认的TAG长度
        if (tag >= 31) {
            while (tag > 0) {
                tag >>= 7;
                encodingDataLen++; //TAG大于一个字节
            }
        }

        encodingDataLen++; //加上Length字节的长度
        if (valueLen > 0x7F) {
            while (valueLen > 0) {
                valueLen >>= 8;
                encodingDataLen++;
            }
        }

        return encodingDataLen;
    }

    public int getTag() {
        return m_tag;
    }

    public boolean setTag(int tag) {
        m_tag = tag;
        if (isStructEncodeTag(m_tag)) {
            m_type = ASNTAGBean.STRUCT;
        }

        return true;
    }

    public int getLength() {
        return m_length;
    }

    public ByteArrayBuffer getValue() {
        if (m_data != null) {
            ByteArrayBuffer value = new ByteArrayBuffer(m_length);
            value.append(m_data.buffer(), m_tlLength, m_length);
            return value;
        }
        return null;
    }

    public int getEncodingDataSize() {
        return m_data.length();
    }

    public ByteArrayBuffer getEncodingData() {
        return m_data;
    }

    public static boolean dump(ByteArrayBuffer data, ZTLVBase item) {
        if (data.isEmpty()) return false;

        ByteArrayBuffer p = new ByteArrayBuffer(data.length());
        p.append(data.buffer(), 0, data.length());
        int max = data.length();
        int tag = 0;
        int length = 0;

        //解析TAG
        int l = 0;
        int index = 0;
        byte i = (byte) (p.buffer()[index] & 0x1F);
        if (i == 0x1F) {
            //TAG元组大于一个字节
            index++;
            if (--max == 0) return false;
            while ((p.buffer()[index] & 0x80) != 0) {
                l <<= 7L;
                l |= p.buffer()[index++] & 0x7F;

                if (--max == 0) return false;
                if (l > (INT_MAX >> 7L)) return false;
            }

            l <<= 7L;
            l |= p.buffer()[index++] & 0x7F;
            if (--max == 0) return false;

            tag = (int) l;
        } else {
            tag = (int) i;
            index++;

            if (--max == 0) return false;
        }

        //解析Length
        length = 0;
        if (max-- < 1) return false;

        if (p.buffer()[index] == 0x80) {
            length = 0;
            index++;
        } else {
            i = (byte) (p.buffer()[index] & 0x7F);
            if ((p.buffer()[index++] & 0x80) != 0) {
                if (i > 4 || max-- == 0) return false;
                while (i-- > 0) {
                    length <<= 8L;
                    if (p.buffer()[index] < 0) {
                        length += 256 + p.buffer()[index++];
                    } else {
                        length += p.buffer()[index++];
                    }
                    if (max-- == 0) return false;
                }
            } else {
                length = i;
            }
        }

        //校验是否length是否和实际的数据长度相符
        if (index + length > data.length()) return false;

        //设置TLV的值
        item.m_tag = tag;
        item.m_length = length;
        item.m_tlLength = index;
        item.m_data.clear();
        if (item.m_data.capacity() < item.m_length + item.m_tlLength) {
            item.m_data = new ByteArrayBuffer(item.m_length + item.m_tlLength);
        }
        item.m_data.append(data.buffer(), 0, item.m_length + item.m_tlLength);
        return true;
    }

    public boolean parse(ByteArrayBuffer data) {
        return dump(data, this);
    }


}
