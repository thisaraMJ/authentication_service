package com.persistent.userauthentication.security;

import com.persistent.userauthentication.filters.JwtRequestFilter;
import com.persistent.userauthentication.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfigure extends WebSecurityConfigurerAdapter {


    @Configuration
    @Order(1)
    public static class JwtWebSecurityConfig extends WebSecurityConfigurerAdapter{
        @Autowired
        private AuthService authService;

        @Autowired
        private JwtRequestFilter jwtRequestFilter;

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.userDetailsService(authService);
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .csrf().disable()
                    .requestMatchers().antMatchers("/jwt/**")
                    .and()
                    .authorizeRequests().antMatchers("/jwt/authenticate").permitAll()
                    .anyRequest().authenticated()
                    .and().sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS); //since we don't want to manage sessions

            http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);

            // "/authenticate" only let in this, other all requests should be authenticated

            //Cross-Site Request Forgery (CSRF) is an attack that forces authenticated users to submit a request to a
            //Web application against which they are currently authenticated.
            //antMatchers(new String[]{"/authenticate", "/not-restricted"})
        }

        @Override
        @Bean
        public AuthenticationManager authenticationManagerBean() throws Exception {
            return super.authenticationManagerBean();
        }

        @Bean
        public PasswordEncoder passwordEncoder(){
            return NoOpPasswordEncoder.getInstance();
        }
    }

    @Configuration
    @Order(3)
    public static class Oauth2SecurityConfig extends WebSecurityConfigurerAdapter{

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .antMatcher("/googleauth/**").authorizeRequests()
//                  .antMatchers("/ldapauth/**").permitAll()
                    .antMatchers("/googleauth/**").authenticated()
                    .and()
                    .oauth2Login();

        }
    }

    @Configuration
    @Order(2)
    public static class LdapSecurityConfig extends WebSecurityConfigurerAdapter{
        @Override
        public void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                    .ldapAuthentication()
                    .userDnPatterns("uid={0},ou=people")
                    .groupSearchBase("ou=groups")
                    .contextSource()
                    .url("ldap://localhost:8389/dc=springframework,dc=org")
                    .and()
                    .passwordCompare()
                    .passwordEncoder(new BCryptPasswordEncoder())
                    .passwordAttribute("userPassword");
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .antMatcher("/ldapauth/**")
//                    .authorizeRequests()
//                    .anyRequest().fullyAuthenticated()
//                    .and()
//                    .formLogin();
//                .antMatcher("/ldapauth/**")
                    .authorizeRequests()
                    .antMatchers("/admin/**").authenticated()
//                    .anyRequest().fullyAuthenticated()
                    .and()
                    .formLogin();
        }

    }


}
