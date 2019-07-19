package com.mycompany.mavenproject2;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Date;

/**
 * Created by David León @datevid on 12/07/2019 12:16.
 */
public class JWTSimpleAuth0 {
	//private static final String keySecret = "secretkey";
	private static final int EXPIRATION_TIME_MILLIS = 1000 * 60*1; // 1 minute expiration

	public static void main(String[] arg){
		System.out.println("----------");
		String keySecret= "your-256-bit-secret";
		String data = "hola mundo";
		String sign = getSignHS256(data,keySecret);
		System.out.println(sign);
		System.out.println("----------");
		DecodedJWT decodedJWT = verifyToken(sign,keySecret);
		decodedJWT.getToken();
		boolean b;
		if (decodedJWT==null) {
			b=false;
		}else{
			b=true;
		}
		System.out.println("verificar:"+b);
	}

	public static String getSignHS256(String data,String keySecret){
		return getSign(data, Algorithm.HMAC256(keySecret));
	}
	public static String getSignHS384(String data,String keySecret){
		return getSign(data, Algorithm.HMAC384(keySecret));
	}
	public static String getSignHS512(String data,String keySecret){
		return getSign(data, Algorithm.HMAC512(keySecret));
	}



	private static String getSign(String data,Algorithm algorithmStr){
		//Algorithm algorithm = Algorithm.HMAC512(keySimetric);
		String sign = JWT.create()
				.withClaim("data", data)
				.withIssuedAt(new Date(System.currentTimeMillis()))
				.withExpiresAt(new Date(System.currentTimeMillis()+EXPIRATION_TIME_MILLIS))
				.sign(algorithmStr);

		return sign;
	}



	public static DecodedJWT verifyToken(String token, String keySimetric){
		try {
			Algorithm algorithm =null;
			DecodedJWT jwt = JWT.decode(token);
			String algorithmStr = jwt.getAlgorithm();
			if (algorithmStr.equals("HS256")) {
				algorithm = Algorithm.HMAC256(keySimetric);
			}else if (algorithmStr.equals("HS384")) {
				algorithm = Algorithm.HMAC384(keySimetric);
			}else if (algorithmStr.equals("HS512")) {
				algorithm = Algorithm.HMAC512(keySimetric);
			}else{
				throw new Exception("Error algorithm");
			}
			return verifyToken(token, algorithm);
		} catch (JWTVerificationException exception){
			return null;
		}catch (Exception exception){
			return null;
		}
	}

	private static DecodedJWT verifyToken(String token, Algorithm algorithm){
		try {
			//Algorithm algorithm = Algorithm.HMAC512(keySimetric);
			JWTVerifier verifier = JWT.require(algorithm)
					//.acceptExpiresAt(60)
					//.acceptLeeway(60)
					//.withIssuer("auth0")
					.build(); //Reusable verifier instance
			DecodedJWT jwt = verifier.verify(token);
			return jwt;
		} catch (JWTVerificationException exception){
			return null;
		}catch (Exception exception){
			return null;
		}
	}

	public static String getFieldNameToken(DecodedJWT jwt, String rowName){
		String fielName;
		try {
			fielName = jwt.getClaim(rowName).asString();
		} catch (Exception e) {
			fielName=null;
		}
		return fielName;
	}
}
