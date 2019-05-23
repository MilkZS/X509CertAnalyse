package com.milkdz.x509.util;

import java.io.UnsupportedEncodingException;


/**
 * byte相关常用方法工具类
 */
public class StringUtil {
	/**
	 * 将byte数组转换为十六进制文本
	 */
	public static String toHex(byte[] buf) {
		if (buf == null || buf.length == 0) {
			return "";
		}
		StringBuilder out = new StringBuilder();    // sonar StringBuffer
		for (int i = 0; i < buf.length; i++) {
			out.append(HEX[(buf[i] >> 4) & 0x0f]).append(HEX[buf[i] & 0x0f]);
		}
		return out.toString();
	}
	/**
	 * 将十六进制文本转换为byte数组
	 */
	public static byte[] hexToBytes(String str) {
		if (str == null) {
			return null;
		}
		char[] hex = str.toCharArray();
		int length = hex.length / 2;
		byte[] raw = new byte[length];
		for (int i = 0; i < length; i++) {
			int high = Character.digit(hex[i * 2], 16);
			int low = Character.digit(hex[i * 2 + 1], 16);
			int value = (high << 4) | low;
			if (value > 127)
				value -= 256;
			raw[i] = (byte) value;
		}
		return raw;
	}
	private final static char[] HEX = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };


	public static byte[] getBytes(String data){
		String encoding = "UTF-8";
		byte [] bytes = new byte[]{};
		try {
			bytes = data.getBytes(encoding);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return  bytes;
	}

	public static void main(String[] args) {
		String hexS = "49434243534D3243414348494C44";
		byte[] b = hexToBytes(hexS);
		System.out.println(new String(b));
	}
}
