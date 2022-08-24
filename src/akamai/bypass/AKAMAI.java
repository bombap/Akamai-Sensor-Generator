package akamai.bypass;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;
import java.util.UUID;
import static akamai.bypass.DeviceInfo.randomScreenSize;
import android.util.Base64;

public class AKAMAI {

	static long uptime = 0;
	static long startTime = System.currentTimeMillis();

	public AKAMAI() {
		uptime = (randomizer.randomWithRange(0, 12)) * 36;
	}

	public long getUptime() {
		Long S = uptime + (System.currentTimeMillis() - startTime);
		return S;
	}

	public DeviceInfo mDeviceInfo = new DeviceInfo("");

	SecretKey aesKey = null;
	SecretKey hmacKey = null;
	String aesKeyEncrypted = null;
	String hamcKeyEncryped = null;

	public String getClientInfo() {
		return mDeviceInfo.getClientInfo();
	}

	public String getSensorData(String email, String pkgName) {
		mDeviceInfo = new DeviceInfo(email);
		String model = mDeviceInfo.model;
		String androidVersion = mDeviceInfo.androidVersion;
		String brand = mDeviceInfo.brand;
		String SDKINT = mDeviceInfo.SDKINT;
		Random random = new Random();
		StringBuilder stringBuilder6 = new StringBuilder();
		stringBuilder6.append("3.2.2-1,2,-94,-100,").append("-1,uaend,-1,").append(randomScreenSize())
				.append(",1,100,1,en,").append(androidVersion).append(",0,").append(model).append(",unknown,qcom,-1,")
				.append(pkgName).append(",-1,-1,").append(UUID.randomUUID().toString()).append(",-1,1,0,REL,")
				.append(208).append(",").append(SDKINT).append(",").append(brand).append(",").append(model)
				.append(",release-keys,user,").append(brand).append(",").append(brand).append("-user%20")
				.append(androidVersion).append("%20").append(208).append("%20release-keys,").append("universal9825,")
				.append(brand).append(",").append(model).append(",").append(brand).append("/").append(brand).append("/")
				.append(model).append(":").append(androidVersion).append("/").append(208).append(":")
				.append("user/release-keys,").append(208).append(",").append(model);
		int length = chrplus(stringBuilder6.toString());
		stringBuilder6.append(",").append(length - 907).append(",").append(Math.max(1, random.nextInt(9999)))
				.append(",").append(System.currentTimeMillis() / 2).append("-1,2,-94,-101,").append("do_unr,dm_en,t_en")
				.append("-1,2,-94,-102,").append("-1,2,-94,-108,").append("-1,2,-94,-117,").append("-1,2,-94,-144,")
				.append("2;333.00;804.00;484202275;}ARARARAQAQARARA").append("-1,2,-94,-142,")
				.append("2;113.81;113.81;2101398081;16}:2;63.18;63.18;2101398081;16}:2;0.00;0.00;2101398081;16}")
				.append("-1,2,-94,-145,").append("2;332.00;885.00;1445233815;}AOAOAPAOAOAOAOA").append("-1,2,-94,-143,")
				.append("2;0.00;0.00;2101398081;16}:2;-4.43;0.00;1575400026;A^vz11|}:2;-2.24;0.00;1575400026;A^vz11|}:2;0.00;0.00;2101398081;16}:2;-8.90;-8.90;2101398081;16}:2;-4.50;-4.50;2101398081;16}:2;0.00;0.00;2101398081;16}:2;0.00;0.00;2101398081;16}:2;0.00;0.00;2101398081;16}")
				.append("-1,2,-94,-115,")
				.append("14836,6367,6304229641,17860583272,24164834116,13008,24,7,16,16,9000,35000,1,837003087987960427,1647704616375,0")
				.append("-1,2,-94,-70,").append("-1,2,-94,-80,").append("-1,2,-94,-120,").append("-1,2,-94,-112,")
				.append("16,342,59,1067,86200,870,79400,793,2647").append("-1,2,-94,-103,");

		String sensor = encryptSensor(stringBuilder6.toString());
		return sensor + "|" + SDKINT + "|" + brand + "|" + model + "|" + androidVersion + "|";
	}

	public static int chrplus(String paramString) {
		if (paramString != null && !paramString.trim().equalsIgnoreCase("")) {
			int b = 0;
			int c = 0;
			try {
				while (b < paramString.length()) {
					char c2 = paramString.charAt(b);
					if (c2 < 128)
						c = c + c2;
					b++;
				}
				return c;
			} catch (Exception e) {
				return -2;
			}
		}
		return -1;
	}

	public String encryptSensor(String str) {
		String result = null;
		try {
			initEncryptKey();

			long uptimeMillis = getUptime();
			Cipher instance = Cipher.getInstance("AES/CBC/PKCS5Padding");
			instance.init(1, aesKey);
			byte[] doFinal = instance.doFinal(str.getBytes());
			long aesUptime = (getUptime() - uptimeMillis) * 1000;
			byte[] iv = instance.getIV();
			byte[] obj = new byte[(doFinal.length + iv.length)];
			System.arraycopy(iv, 0, obj, 0, iv.length);
			System.arraycopy(doFinal, 0, obj, iv.length, doFinal.length);
			uptimeMillis = getUptime();
			Key secretKeySpec = new SecretKeySpec(hmacKey.getEncoded(), "HmacSHA256");
			Mac instance2 = Mac.getInstance("HmacSHA256");
			instance2.init(secretKeySpec);
			iv = instance2.doFinal(obj);
			doFinal = new byte[(obj.length + iv.length)];
			long hmackUptime = (getUptime() - uptimeMillis) * 1000;
			System.arraycopy(obj, 0, doFinal, 0, obj.length);
			System.arraycopy(iv, 0, doFinal, obj.length, iv.length);
			uptimeMillis = getUptime();
			String encryptedData = Base64.encodeToString(doFinal, 2);
			long b64uptime = 1000 * (getUptime() - uptimeMillis);

			StringBuilder sb = new StringBuilder();
			sb.append("2,a,");
			sb.append(aesKeyEncrypted);
			sb.append(",");
			sb.append(hamcKeyEncryped);
			sb.append("$");
			sb.append(encryptedData);
			sb.append("$");
			sb.append(aesUptime).append(",").append(hmackUptime).append(",").append(b64uptime);
			sb.append("$$");
			result = sb.toString();
		} catch (Exception e) {
		}
		return result;
	}

	private void initEncryptKey() {
		if (aesKey != null) {
			return;
		}
		try {
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			aesKey = keyGen.generateKey();

			KeyGenerator hmacKeyGen = KeyGenerator.getInstance("HmacSHA256");
			hmacKey = hmacKeyGen.generateKey();
			String key = null;
			key = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4sA7vA7N/t1SRBS8tugM2X4bByl0jaCZLqxPOql+qZ3sP4UFayqJTvXjd7eTjMwg1T70PnmPWyh1hfQr4s12oSVphTKAjPiWmEBvcpnPPMjr5fGgv0w6+KM9DLTxcktThPZAGoVcoyM/cTO/YsAMIxlmTzpXBaxddHRwi8S2NvwIDAQAB";
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decode(key, 0));

			KeyFactory factory = KeyFactory.getInstance("RSA");
			PublicKey rsaKey = factory.generatePublic(keySpec);

			Cipher rsaInstance = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
			rsaInstance.init(1, rsaKey);
			aesKeyEncrypted = Base64.encodeToString(rsaInstance.doFinal(aesKey.getEncoded()), 2);
			hamcKeyEncryped = Base64.encodeToString(rsaInstance.doFinal(hmacKey.getEncoded()), 2);
		} catch (Exception e) {
		}
	}

	public static void main(String[] args) throws Exception {
		System.out.println(new AKAMAI().getSensorData(args[0], args[1]));
	}
}
