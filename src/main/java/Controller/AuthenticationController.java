package Controller;


import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import javax.servlet.http.HttpServletRequest;

import Config.JwtUtil;
import Model.AuthenticationRequest;
import Model.AuthenticationResponse;
import Service.CustomUserDetailsService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;


import io.jsonwebtoken.impl.DefaultClaims;

@RestController
public class AuthenticationController {

    private AuthenticationManager authenticationManager;

    private CustomUserDetailsService userDetailsService;

    private JwtUtil jwtUtil;

    public AuthenticationController(AuthenticationManager authenticationManager, CustomUserDetailsService userDetailsService, JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.jwtUtil = jwtUtil;
    }

    @RequestMapping(value = "/authenticate", method = RequestMethod.POST)
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest)
            throws Exception {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    authenticationRequest.getUsername(), authenticationRequest.getPassword()));
        } catch (DisabledException e) {
            throw new Exception("USER_DISABLED", e);
        } catch (BadCredentialsException e) {
            throw new Exception("INVALID_CREDENTIALS", e);
        }

        UserDetails userdetails = userDetailsService.loadUserByUsername(authenticationRequest.getUsername());
        String token = jwtUtil.generateToken(userdetails);
        return ResponseEntity.ok(new AuthenticationResponse(token));
    }

    @RequestMapping(value = "/refreshtoken", method = RequestMethod.GET)
    public ResponseEntity<?> refreshtoken(HttpServletRequest request) throws Exception {
        // From the HttpRequest get the claims
        // claims :{sub=ashish@gmail.com, isAdmin=true, exp=1665987684, iat=1665987584}
        DefaultClaims claims = (io.jsonwebtoken.impl.DefaultClaims) request.getAttribute("claims");
        System.out.println("++++++++++++++++ AuthenticationController +++++++++++++++++++++");
        System.out.println("claims :"+ claims);


        //expectedMap :{sub=ashish@gmail.com, isAdmin=true, exp=1665987684, iat=1665987584}
        Map<String, Object> expectedMap = getMapFromIoJsonwebtokenClaims(claims);
        System.out.println("++++++++++++++++++++ AuthenticationController ++++++++++++++++++++");
        System.out.println("expectedMap :"+ expectedMap);


        //token :eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhc2hpc2hAZ21haWwuY29tIiwiaXNBZG1pbiI6dHJ1ZSwiZXhwIjoxNjY1OTk2NzA5LCJpYXQiOjE2NjU5ODc3MDl9
        // .Miwxgu13Vg4XTb7ofUAe0lCQto6-rL96cNq8cet7Eu671T31kXpjTrN2weVIMJ2EpqLt_eINjwPrv2e3jQUqvg
        String token = jwtUtil.doGenerateRefreshToken(expectedMap, expectedMap.get("sub").toString());
        System.out.println("++++++++++++++++++++++ AuthenticationController ++++++++++++++++++++++");
        System.out.println("token :"+ token);
        return ResponseEntity.ok(new AuthenticationResponse(token));
    }

    public Map<String, Object> getMapFromIoJsonwebtokenClaims(DefaultClaims claims) {
        Map<String, Object> expectedMap = new HashMap<String, Object>();

        // entrySet() returns a set view of all entries
        // for-each loop access each entry from the view
        for (Entry<String, Object> entry : claims.entrySet())
        {
            expectedMap.put(entry.getKey(), entry.getValue());
            System.out.println("++++++++++++++++++ AuthenticationController +++++++++++++++++++++++++");
            System.out.println(entry);
        }
        return expectedMap;
    }
}