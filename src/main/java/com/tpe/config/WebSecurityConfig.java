package com.tpe.config;
import com.tpe.security.AuthTokenFilter;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.Filter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@AllArgsConstructor

public class WebSecurityConfig extends WebSecurityConfigurerAdapter {


    @Autowired
    private UserDetailsService userDetailsService;


    @Override
    protected void configure(HttpSecurity http) throws Exception {
      http.csrf().disable().sessionManagement().
              sessionCreationPolicy(SessionCreationPolicy.STATELESS)./// because we are creating RestFul API
        and()
              .authorizeRequests()
              .antMatchers("/register","/login")
              .permitAll()
              .anyRequest()
              .authenticated();

        // to insert the custom authTokenFilter before the built-in
        // UsernamePasswordAuthenticationFilter in the filter chain.
        http.addFilterBefore(authTokenFilter(), UsernamePasswordAuthenticationFilter.class);

    }


    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();//4-31
    }

    @Bean
    public AuthTokenFilter authTokenFilter(){
        return new AuthTokenFilter();
    }


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //this is another way to introduce useDetails and password to Authentication manager
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    @Bean
    protected AuthenticationManager authenticationManager() throws Exception{
        return super.authenticationManager();
    }

}
