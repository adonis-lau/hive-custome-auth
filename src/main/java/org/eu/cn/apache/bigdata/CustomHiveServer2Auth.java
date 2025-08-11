package org.eu.cn.apache.bigdata;

import org.apache.hadoop.hive.conf.HiveConf;
import org.apache.hive.service.auth.PasswdAuthenticationProvider;

import javax.security.sasl.AuthenticationException;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


/**
 * Custom HiveServer2 Auth
 *
 * @author adonis lau
 * @email adonis.liu@apache.cn.eu.org
 * @date 2025-08-11
 */
public class CustomHiveServer2Auth implements PasswdAuthenticationProvider {

    private final HiveConf hiveConf;

    public CustomHiveServer2Auth() {
        this.hiveConf = new HiveConf();
    }

    @Override
    public void authenticate(String username, String password) throws AuthenticationException {
        String passMd5;
        try {
            passMd5 = toMD5(password);
        } catch (NoSuchAlgorithmException e) {
            throw new AuthenticationException("MD5 algorithm not available.", e);
        }

        String filePath = hiveConf.get("hive.server2.custom.authentication.file");
        if (filePath == null || filePath.trim().isEmpty()) {
            throw new AuthenticationException("Hive custom authentication file not specified in hive-site.xml (hive.server2.custom.authentication.file).");
        }
        System.out.println("Using custom authentication file: " + filePath);

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",", 2);
                if (parts.length == 2 && parts[0].equals(username) && parts[1].equals(passMd5)) {
                    System.out.println("User [" + username + "] authenticated successfully.");
                    return; // 认证成功
                }
            }
        } catch (IOException e) {
            throw new AuthenticationException("Failed to read authentication file: " + filePath, e);
        }

        // 如果循环结束仍未找到匹配项
        System.out.println("User [" + username + "] authentication failed.");
        throw new AuthenticationException("User [" + username + "] authentication failed.");
    }

    private String toMD5(String str) throws NoSuchAlgorithmException {
        if (str == null) {
            return null;
        }
        MessageDigest digest = MessageDigest.getInstance("MD5");
        byte[] hash = digest.digest(str.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
