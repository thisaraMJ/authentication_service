package com.persistent.userauthentication.util.basicauth;

import com.persistent.userauthentication.model.AuthenticationRequest;
import com.persistent.userauthentication.service.AuthService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;


@Service
public class JwtUtil {

    @Autowired
    private final AuthService authService;

    public JwtUtil(AuthService authService) { this.authService = authService; }

//    private String SECRET_KEY = "secret"; //secret key should be more complex if this a real world application


    public String extractUsername(String token, Long id) {
        return extractClaim(token, id, Claims::getSubject);
    }

    public Date extractExpiration(String token, Long id) {
        return extractClaim(token, id, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Long id,Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token, id);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token, Long id) {
        AuthenticationRequest user = authService.findUserById(id);
        String SECRET_KEY = user.getSecret();
        return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token, Long id) {
        return extractExpiration(token, id).before(new Date());
    }

    private String createToken(Map<String, Object> claims, String subject, int lifeTime) {
        AuthenticationRequest user = authService.getUserByUsername(subject); //subject is => userDetails.getUsername()
        String SECRET_KEY = user.getSecret();
        long id = user.getId();

        String jwt = Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * lifeTime)) //1000 * 60 * 60 * 10
                .signWith(SignatureAlgorithm.RS256, SECRET_KEY).compact(); //HS256

        return jwt+"$"+id; //concatenate jwt with user id
    }

    public String generateToken(UserDetails userDetails, int lifeTime) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userDetails.getUsername(), lifeTime);
    }


    public Boolean validateToken(String token, Long id, UserDetails userDetails) {
        final String username = extractUsername(token, id);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token, id));
    }

    public String extendToken(String token, int lifeTime) {
        String jwt = token.substring(7);
        Long id = Long.parseLong(jwt.substring(jwt.lastIndexOf("$") + 1)); //extract id from jwt
        jwt = jwt.substring(0, jwt.indexOf("$")); //remove id from jwt

        String userName = extractUsername(jwt, id);

        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userName, lifeTime);
    }

    public static String generateRandomSecret(int len, int randNumOrigin, int randNumBound) {
        SecureRandom random = new SecureRandom();
        return random.ints(randNumOrigin, randNumBound + 1)
                .filter(i -> Character.isAlphabetic(i) || Character.isDigit(i))
                .limit(len)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint,
                        StringBuilder::append)
                .toString();
    }

    public void invalidateToken(String token) {
        String jwt = token.substring(7);
        Long id = Long.parseLong(jwt.substring(jwt.lastIndexOf("$") + 1)); //extract id from jwt
        jwt = jwt.substring(0, jwt.indexOf("$")); //remove id from jwt

        String userName = extractUsername(jwt, id);

        int len = 12, randNumOrigin = 48, randNumBound = 122;
        String newSecret = generateRandomSecret(len, randNumOrigin, randNumBound);

        authService.updateSecretByUsername(userName, newSecret);
    }
}
