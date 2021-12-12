package com.persistent.userauthentication.security;

import com.persistent.userauthentication.filters.JwtRequestFilter;
import com.persistent.userauthentication.service.AuthService;
import com.persistent.userauthentication.util.ldapauth.JwtTokenProvider;
import com.persistent.userauthentication.util.ldapauth.LdapAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
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
                    .authorizeRequests().antMatchers("/jwt/auth-server").permitAll()
                    .anyRequest().authenticated()
                    .and().sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS); //since we don't want to manage sessions

            http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);

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
    @Order(2)
    public static class LdapSecurityConfig extends WebSecurityConfigurerAdapter{

        private Environment env;

        public LdapSecurityConfig(Environment env){
            this.env = env;
        }

        @Override
        public void configure(AuthenticationManagerBuilder auth) throws Exception
        {
            auth.authenticationProvider(new LdapAuthenticationProvider(env)).eraseCredentials(false);
               /* .ldapAuthentication()
                .passwordCompare()
                .passwordEncoder(new BCryptPasswordEncoder())
                .passwordAttribute("userPassword");*/
        }

        @Override
        protected void configure(HttpSecurity httpSecurity) throws Exception
        {
            httpSecurity
                    .csrf()
                    .disable()
                    .requestMatchers().antMatchers("/ldap/**","/login")
                    .and()
                    .authorizeRequests()
                    .antMatchers("/ldap/auth-server").permitAll()
                    .anyRequest()
                    .authenticated()
                    .and()
                    .httpBasic();

        }

        @Bean
        public JwtTokenProvider provider(){
            return new JwtTokenProvider();
        }

    }


    @Configuration
    @Order(3)
    public static class Oauth2SecurityConfig extends WebSecurityConfigurerAdapter{

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .csrf().disable()
                    .requestMatchers().antMatchers("/google/**","/oauth2/authorization/google","/login/oauth2/code/google")
                    .and()
                    .authorizeRequests().antMatchers("/ldap/**","/jwt/**").permitAll()
                    .anyRequest().fullyAuthenticated()
                    .and()
                    .oauth2Login();
        }
    }

}
