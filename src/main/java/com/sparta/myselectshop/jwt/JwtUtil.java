package com.sparta.myselectshop.jwt;


import com.sparta.myselectshop.entity.UserRoleEnum;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.security.Key;
import java.util.Base64;
import java.util.Date;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtUtil {

    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String AUTHORIZATION_KEY = "auth";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final long TOKEN_TIME = 60 * 60 * 1000L;

    @Value("${jwt.secret.key}")
    private String secretKey;
    private Key key;
    private final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

    @PostConstruct
    public void init() {
        byte[] bytes = Base64.getDecoder().decode(secretKey);
        key = Keys.hmacShaKeyFor(bytes);
    }

    // header 토큰을 가져오기
    public String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(7);
        }
        return null;
    }

    // 토큰 생성
    public String createToken(String username, UserRoleEnum role) {
        Date date = new Date();

        return BEARER_PREFIX +
                Jwts.builder()
                        //어떠한 공간에 Username을 넣어줄거다
                        .setSubject(username)
                        //어떠한 공간에 사용자의 권한을 넣어줄꺼고 그 권한을 가져올떄는 OAuthkey를 사용해서 넣을거다
                        .claim(AUTHORIZATION_KEY, role)
                        //이토큰을 언제까지 유효하게 열어둘지, Date는 토큰생성된 dage이며, getTime은 현재 토큰시간 60 * 60 * 1000L
                        .setExpiration(new Date(date.getTime() + TOKEN_TIME))
                        //토큰이 언제 만들어졋는지에 대한 내용 Key객체
                        .setIssuedAt(date)
                        //secreat key값 암호화 알고리즘 hs256
                        .signWith(key, signatureAlgorithm)
                        //string형식 JWT 토큰 반환
                        .compact();
    }

    // 토큰 검증
    public boolean validateToken(String token) {
        try {//내부적으로 토큰을 검중해준다. 아래꺼
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (SecurityException | MalformedJwtException e) {
            log.info("Invalid JWT signature, 유효하지 않는 JWT 서명 입니다.");
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT token, 만료된 JWT token 입니다.");
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT token, 지원되지 않는 JWT 토큰 입니다.");
        } catch (IllegalArgumentException e) {
            log.info("JWT claims is empty, 잘못된 JWT 토큰 입니다.");
        }
        return false;
    }

    // 토큰에서 사용자 정보 가져오기
    // 위와 코드가 비슷하나 마지막에 getBody()로 되어 있다.
    // 위에서 유효한 토큰으로 검증이 되었기 때문에 유효한 토큰이라 그래서 Try Catch가 없다

    public Claims getUserInfoFromToken(String token) {
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
    }

}